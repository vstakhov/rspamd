/*-
 * Copyright 2016 Vsevolod Stakhov
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "config.h"
#include "libserver/dynamic_cfg.h"
#include "libserver/cfg_file_private.h"
#include "libutil/rrd.h"
#include "libserver/maps/map.h"
#include "libserver/maps/map_helpers.h"
#include "libserver/maps/map_private.h"
#include "libserver/http/http_private.h"
#include "libserver/http/http_router.h"
#include "libstat/stat_api.h"
#include "rspamd.h"
#include "libserver/worker_util.h"
#include "worker_private.h"
#include "lua/lua_common.h"
#include "cryptobox.h"
#include "ottery.h"
#include "fuzzy_wire.h"
#include "unix-std.h"
#include "utlist.h"
#include "libmime/lang_detection.h"
#include <math.h>

/* 60 seconds for worker's IO */
#define DEFAULT_WORKER_IO_TIMEOUT 60000

/* HTTP paths */
#define PATH_AUTH "/auth"
#define PATH_SYMBOLS "/symbols"
#define PATH_ACTIONS "/actions"
#define PATH_MAPS "/maps"
#define PATH_GET_MAP "/getmap"
#define PATH_GRAPH "/graph"
#define PATH_PIE_CHART "/pie"
#define PATH_HEALTHY "/healthy"
#define PATH_HISTORY "/history"
#define PATH_HISTORY_RESET "/historyreset"
#define PATH_LEARN_SPAM "/learnspam"
#define PATH_LEARN_HAM "/learnham"
#define PATH_METRICS "/metrics"
#define PATH_READY "/ready"
#define PATH_SAVE_ACTIONS "/saveactions"
#define PATH_SAVE_SYMBOLS "/savesymbols"
#define PATH_SAVE_MAP "/savemap"
#define PATH_SCAN "/scan"
#define PATH_CHECK "/check"
#define PATH_CHECKV2 "/checkv2"
#define PATH_STAT "/stat"
#define PATH_STAT_RESET "/statreset"
#define PATH_COUNTERS "/counters"
#define PATH_ERRORS "/errors"
#define PATH_NEIGHBOURS "/neighbours"
#define PATH_PLUGINS "/plugins"
#define PATH_PING "/ping"

#define msg_err_session(...) rspamd_default_log_function(G_LOG_LEVEL_CRITICAL, \
        session->pool->tag.tagname, session->pool->tag.uid, \
        G_STRFUNC, \
        __VA_ARGS__)
#define msg_warn_session(...)   rspamd_default_log_function (G_LOG_LEVEL_WARNING, \
        session->pool->tag.tagname, session->pool->tag.uid, \
        G_STRFUNC, \
        __VA_ARGS__)
#define msg_info_session(...)   rspamd_default_log_function (G_LOG_LEVEL_INFO, \
        session->pool->tag.tagname, session->pool->tag.uid, \
        G_STRFUNC, \
        __VA_ARGS__)
#define msg_err_ctx(...) rspamd_default_log_function(G_LOG_LEVEL_CRITICAL, \
        "controller", ctx->cfg->cfg_pool->tag.uid, \
        G_STRFUNC, \
        __VA_ARGS__)
#define msg_warn_ctx(...)   rspamd_default_log_function (G_LOG_LEVEL_WARNING, \
        "controller", ctx->cfg->cfg_pool->tag.uid, \
        G_STRFUNC, \
        __VA_ARGS__)
#define msg_info_ctx(...)   rspamd_default_log_function (G_LOG_LEVEL_INFO, \
        "controller", ctx->cfg->cfg_pool->tag.uid, \
        G_STRFUNC, \
        __VA_ARGS__)

#define msg_debug_session(...)  rspamd_conditional_debug_fast (NULL, session->from_addr, \
        rspamd_controller_log_id, "controller", session->pool->tag.uid, \
        G_STRFUNC, \
        __VA_ARGS__)

INIT_LOG_MODULE(controller)

/* Graph colors */
#define COLOR_CLEAN "#58A458"
#define COLOR_PROBABLE_SPAM "#D67E7E"
#define COLOR_GREYLIST "#A0A0A0"
#define COLOR_REJECT "#CB4B4B"
#define COLOR_TOTAL "#9440ED"

static const guint64 rspamd_controller_ctx_magic = 0xf72697805e6941faULL;

extern void fuzzy_stat_command (struct rspamd_task *task);

gpointer init_controller_worker (struct rspamd_config *cfg);
void start_controller_worker (struct rspamd_worker *worker);

worker_t controller_worker = {
	"controller",                   /* Name */
	init_controller_worker,         /* Init function */
	start_controller_worker,        /* Start function */
	RSPAMD_WORKER_HAS_SOCKET | RSPAMD_WORKER_KILLABLE |
			RSPAMD_WORKER_SCANNER | RSPAMD_WORKER_CONTROLLER,
	RSPAMD_WORKER_SOCKET_TCP,       /* TCP socket */
	RSPAMD_WORKER_VER       /* Version info */
};
/*
 * Worker's context
 */
struct rspamd_controller_worker_ctx {
	guint64 magic;
	/* Events base */
	struct ev_loop *event_loop;
	/* DNS resolver */
	struct rspamd_dns_resolver *resolver;
	/* Config */
	struct rspamd_config *cfg;
	/* END OF COMMON PART */
	ev_tstamp timeout;
	/* Whether we use ssl for this server */
	gboolean use_ssl;
	/* Webui password */
	gchar *password;
	/* Privilleged password */
	gchar *enable_password;
	/* Cached versions of the passwords */
	rspamd_ftok_t cached_password;
	rspamd_ftok_t cached_enable_password;
	/* HTTP server */
	struct rspamd_http_context *http_ctx;
	struct rspamd_http_connection_router *http;
	/* Server's start time */
	ev_tstamp start_time;
	/* Main server */
	struct rspamd_main *srv;
	/* SSL cert */
	gchar *ssl_cert;
	/* SSL private key */
	gchar *ssl_key;
	/* A map of secure IP */
	const ucl_object_t *secure_ip;
	struct rspamd_radix_map_helper *secure_map;

	/* Static files dir */
	gchar *static_files_dir;

	/* Custom commands registered by plugins */
	GHashTable *custom_commands;

	/* Plugins registered from lua */
	GHashTable *plugins;

	/* Worker */
	struct rspamd_worker *worker;

	/* Local keypair */
	gpointer key;

	struct rspamd_rrd_file *rrd;
	struct rspamd_lang_detector *lang_det;
	gdouble task_timeout;
};

struct rspamd_controller_plugin_cbdata {
	lua_State *L;
	struct rspamd_controller_worker_ctx *ctx;
	gchar *plugin;
	struct ucl_lua_funcdata *handler;
	ucl_object_t *obj;
	gboolean is_enable;
	gboolean need_task;
	guint version;
};

static gboolean
rspamd_is_encrypted_password (const gchar *password,
		struct rspamd_controller_pbkdf const **pbkdf)
{
	const gchar *start, *end;
	gint64 id;
	gsize size, i;
	gboolean ret = FALSE;
	const struct rspamd_controller_pbkdf *p;

	if (password[0] == '$') {
		/* Parse id */
		start = password + 1;
		end = start;
		size = 0;

		while (*end != '\0' && g_ascii_isdigit (*end)) {
			size++;
			end++;
		}

		if (size > 0) {
			gchar *endptr;
			id = strtoul (start, &endptr, 10);

			if ((endptr == NULL || *endptr == *end)) {
				for (i = 0; i < RSPAMD_PBKDF_ID_MAX - 1; i ++) {
					p = &pbkdf_list[i];

					if (p->id == id) {
						ret = TRUE;
						if (pbkdf != NULL) {
							*pbkdf = &pbkdf_list[i];
						}

						break;
					}
				}
			}
		}
	}

	return ret;
}

static const gchar *
rspamd_encrypted_password_get_str (const gchar * password, gsize skip,
		gsize * length)
{
	const gchar *str, *start, *end;
	gsize size;

	start = password + skip;
	end = start;
	size = 0;

	while (*end != '\0' && g_ascii_isalnum (*end)) {
		size++;
		end++;
	}

	if (size) {
		str = start;
		*length = size;
	}
	else {
		str = NULL;
	}

	return str;
}

static gboolean
rspamd_check_encrypted_password (struct rspamd_controller_worker_ctx *ctx,
		const rspamd_ftok_t * password, const gchar * check,
		const struct rspamd_controller_pbkdf *pbkdf,
		gboolean is_enable)
{
	const gchar *salt, *hash;
	gchar *salt_decoded, *key_decoded;
	gsize salt_len = 0, key_len = 0;
	gboolean ret = TRUE;
	guchar *local_key;
	rspamd_ftok_t *cache;
	gpointer m;

	/* First of all check cached versions to save resources */
	if (is_enable && ctx->cached_enable_password.len != 0) {
		if (password->len != ctx->cached_enable_password.len ||
				!rspamd_constant_memcmp (password->begin,
						ctx->cached_enable_password.begin, password->len)) {
			msg_info_ctx ("incorrect or absent enable password has been specified");
			return FALSE;
		}

		return TRUE;
	}
	else if (!is_enable && ctx->cached_password.len != 0) {
		if (password->len != ctx->cached_password.len ||
				!rspamd_constant_memcmp (password->begin,
						ctx->cached_password.begin, password->len)) {
			/* We still need to check enable password here */
			if (ctx->cached_enable_password.len != 0) {
				if (password->len != ctx->cached_enable_password.len ||
						!rspamd_constant_memcmp (password->begin,
								ctx->cached_enable_password.begin,
								password->len)) {
					msg_info_ctx (
							"incorrect or absent password has been specified");

					return FALSE;
				}
				else {
					/* Cached matched */
					return TRUE;
				}
			}
			else {
				/* We might want to check uncached version */
				goto check_uncached;
			}
		}
		else {
			/* Cached matched */
			return TRUE;
		}
	}

check_uncached:
	g_assert (pbkdf != NULL);
	/* get salt */
	salt = rspamd_encrypted_password_get_str (check, 3, &salt_len);
	/* get hash */
	hash = rspamd_encrypted_password_get_str (check, 3 + salt_len + 1,
			&key_len);
	if (salt != NULL && hash != NULL) {

		/* decode salt */
		salt_decoded = rspamd_decode_base32 (salt, salt_len, &salt_len, RSPAMD_BASE32_DEFAULT);

		if (salt_decoded == NULL || salt_len != pbkdf->salt_len) {
			/* We have some unknown salt here */
			msg_info_ctx ("incorrect salt: %z, while %z expected",
					salt_len, pbkdf->salt_len);
			return FALSE;
		}

		key_decoded = rspamd_decode_base32 (hash, key_len, &key_len, RSPAMD_BASE32_DEFAULT);

		if (key_decoded == NULL || key_len != pbkdf->key_len) {
			/* We have some unknown salt here */
			msg_info_ctx ("incorrect key: %z, while %z expected",
					key_len, pbkdf->key_len);
			return FALSE;
		}

		local_key = g_alloca (pbkdf->key_len);
		rspamd_cryptobox_pbkdf (password->begin, password->len,
				salt_decoded, salt_len,
				local_key, pbkdf->key_len, pbkdf->complexity,
				pbkdf->type);

		if (!rspamd_constant_memcmp (key_decoded, local_key, pbkdf->key_len)) {
			msg_info_ctx ("incorrect or absent password has been specified");
			ret = FALSE;
		}

		g_free (salt_decoded);
		g_free (key_decoded);
	}

	if (ret) {
		/* Save cached version */
		cache = is_enable ? &ctx->cached_enable_password : &ctx->cached_password;

		if (cache->len == 0) {
			/* Mmap region */
#ifdef MAP_NOCORE
			m = mmap (NULL, password->len, PROT_WRITE,
					MAP_PRIVATE | MAP_ANON | MAP_NOCORE, -1, 0);
#else
			m = mmap (NULL, password->len, PROT_WRITE,
					MAP_PRIVATE | MAP_ANON, -1, 0);
#endif
			if (m != MAP_FAILED) {
				memcpy (m, password->begin, password->len);
				(void)mprotect (m, password->len, PROT_READ);
				(void)mlock (m, password->len);
				cache->begin = m;
				cache->len = password->len;
			}
			else {
				msg_err_ctx ("cannot store cached password, mmap failed: %s",
						strerror (errno));
			}
		}
	}

	return ret;
}

/**
 * Checks for X-Forwarded-For header and update client's address if needed
 *
 * This function is intended to be called for a trusted client to ensure that
 * a request is not proxied through it
 * @return 0 if no forwarded found, 1 if forwarded found and it is yet trusted
 * and -1 if forwarded is denied
 */
static gint
rspamd_controller_check_forwarded (struct rspamd_controller_session *session,
		struct rspamd_http_message *msg,
		struct rspamd_controller_worker_ctx *ctx)
{
	const rspamd_ftok_t *hdr;
	const gchar *comma;
	const char *hdr_name = "X-Forwarded-For", *alt_hdr_name = "X-Real-IP";
	char ip_buf[INET6_ADDRSTRLEN + 1];
	rspamd_inet_addr_t *addr = NULL;
	gint ret = 0;

	hdr = rspamd_http_message_find_header (msg, hdr_name);

	if (hdr) {
		/*
		 * We need to parse and update the header
		 * X-Forwarded-For: client, proxy1, proxy2
		 */
		comma = rspamd_memrchr (hdr->begin, ',', hdr->len);
		if (comma != NULL) {
			while (comma < hdr->begin + hdr->len &&
					(*comma == ',' || g_ascii_isspace (*comma))) {
				comma ++;
			}
		}
		else {
			comma = hdr->begin;
		}
		if (rspamd_parse_inet_address (&addr, comma,
				(hdr->begin + hdr->len) - comma,
				RSPAMD_INET_ADDRESS_PARSE_NO_UNIX)) {
			/* We have addr now, so check if it is still trusted */
			if (ctx->secure_map &&
					rspamd_match_radix_map_addr (ctx->secure_map, addr) != NULL) {
				/* rspamd_inet_address_to_string is not reentrant */
				rspamd_strlcpy (ip_buf, rspamd_inet_address_to_string (addr),
						sizeof (ip_buf));
				msg_info_session ("allow unauthorized proxied connection "
						"from a trusted IP %s via %s",
						ip_buf,
						rspamd_inet_address_to_string (session->from_addr));
				ret = 1;
			}
			else {
				ret = -1;
			}

			rspamd_inet_address_free (addr);
		}
		else {
			msg_warn_session ("cannot parse forwarded IP: %T", hdr);
			ret = -1;
		}
	}
	else {
		/* Try also X-Real-IP */
		hdr = rspamd_http_message_find_header (msg, alt_hdr_name);

		if (hdr) {
			if (rspamd_parse_inet_address (&addr, hdr->begin, hdr->len,
					RSPAMD_INET_ADDRESS_PARSE_NO_UNIX)) {
				/* We have addr now, so check if it is still trusted */
				if (ctx->secure_map &&
						rspamd_match_radix_map_addr (ctx->secure_map, addr) != NULL) {
					/* rspamd_inet_address_to_string is not reentrant */
					rspamd_strlcpy (ip_buf, rspamd_inet_address_to_string (addr),
							sizeof (ip_buf));
					msg_info_session ("allow unauthorized proxied connection "
							"from a trusted IP %s via %s",
							ip_buf,
							rspamd_inet_address_to_string (session->from_addr));
					ret = 1;
				}
				else {
					ret = -1;
				}

				rspamd_inet_address_free (addr);
			}
			else {
				msg_warn_session ("cannot parse real IP: %T", hdr);
				ret = -1;
			}
		}
	}

	return ret;
}

/* Check for password if it is required by configuration */
static gboolean
rspamd_controller_check_password (struct rspamd_http_connection_entry *entry,
		struct rspamd_controller_session *session,
		struct rspamd_http_message *msg, gboolean is_enable)
{
	const gchar *check;
	const rspamd_ftok_t *password;
	rspamd_ftok_t lookup;
	GHashTable *query_args = NULL;
	struct rspamd_controller_worker_ctx *ctx = session->ctx;
	gboolean check_normal = TRUE, check_enable = TRUE, ret = TRUE,
		use_enable = FALSE;
	const struct rspamd_controller_pbkdf *pbkdf = NULL;

	/* Access list logic */
	if (rspamd_inet_address_get_af (session->from_addr) == AF_UNIX) {
		ret = rspamd_controller_check_forwarded (session, msg, ctx);

		if (ret == 1) {
			session->is_enable = TRUE;

			return TRUE;
		}
		else if (ret == 0) {
			/* No forwarded found */
			msg_info_session ("allow unauthorized connection from a unix socket");
			session->is_enable = TRUE;

			return TRUE;
		}
	}
	else if (ctx->secure_map
			&& rspamd_match_radix_map_addr (ctx->secure_map, session->from_addr)
					!= NULL) {
		ret = rspamd_controller_check_forwarded (session, msg, ctx);

		if (ret == 1) {
			session->is_enable = TRUE;

			return TRUE;
		}
		else if (ret == 0) {
			/* No forwarded found */
			msg_info_session ("allow unauthorized connection from a trusted IP %s",
							rspamd_inet_address_to_string (session->from_addr));
			session->is_enable = TRUE;

			return TRUE;
		}
	}

	/* Password logic */
	password = rspamd_http_message_find_header (msg, "Password");

	if (password == NULL) {
		/* Try to get password from query args */
		query_args = rspamd_http_message_parse_query (msg);

		lookup.begin = (gchar *)"password";
		lookup.len = sizeof ("password") - 1;

		password = g_hash_table_lookup (query_args, &lookup);
	}

	if (password == NULL) {
		if (ctx->secure_map == NULL) {
			if (ctx->password == NULL && !is_enable) {
				return TRUE;
			}
			else if (is_enable && (ctx->password == NULL &&
					ctx->enable_password == NULL)) {
				session->is_enable = TRUE;
				return TRUE;
			}
		}

		msg_info_session ("absent password has been specified; source ip: %s",
				rspamd_inet_address_to_string_pretty (session->from_addr));
		ret = FALSE;
	}
	else {
		if (rspamd_ftok_cstr_equal (password, "q1", FALSE) ||
				rspamd_ftok_cstr_equal (password, "q2", FALSE)) {
			msg_info_session ("deny default password for remote access; source ip: %s",
					rspamd_inet_address_to_string_pretty (session->from_addr));
			ret = FALSE;
			goto end;
		}

		if (is_enable) {
			/* For privileged commands we strictly require enable password */
			if (ctx->enable_password != NULL) {
				check = ctx->enable_password;
				use_enable = TRUE;
			}
			else {
				/* Use just a password (legacy mode) */
				msg_info(
						"using password as enable_password for a privileged command");
				check = ctx->password;
			}

			if (check != NULL) {
				if (!rspamd_is_encrypted_password (check, &pbkdf)) {
					ret = FALSE;

					if (strlen (check) == password->len) {
						ret = rspamd_constant_memcmp (password->begin, check,
								password->len);
					}
				}
				else {
					ret = rspamd_check_encrypted_password (ctx, password, check,
							pbkdf, use_enable);
				}
			}
			else {
				msg_warn_session (
						"no password to check while executing a privileged command; source ip: %s",
						rspamd_inet_address_to_string_pretty (session->from_addr));
				ret = FALSE;
			}

			if (ret) {
				session->is_enable = TRUE;
			}
		}
		else {
			/* Accept both normal and enable passwords */
			if (ctx->password != NULL) {
				check = ctx->password;

				if (!rspamd_is_encrypted_password (check, &pbkdf)) {
					check_normal = FALSE;

					if (strlen (check) == password->len) {
						check_normal = rspamd_constant_memcmp (password->begin,
								check,
								password->len);
					}
				}
				else {
					check_normal = rspamd_check_encrypted_password (ctx,
							password,
							check, pbkdf, FALSE);
				}

			}
			else {
				check_normal = FALSE;
			}

			if (ctx->enable_password != NULL) {
				check = ctx->enable_password;

				if (!rspamd_is_encrypted_password (check, &pbkdf)) {
					check_enable = FALSE;

					if (strlen (check) == password->len) {
						check_enable = rspamd_constant_memcmp (password->begin,
								check,
								password->len);
					}
				}
				else {
					check_enable = rspamd_check_encrypted_password (ctx,
							password,
							check, pbkdf, TRUE);
				}

				if (check_enable) {
					session->is_enable = TRUE;
				}
			}
			else {
				check_enable = FALSE;

				if (check_normal) {
					/*
					 * If no enable password is specified use normal password as
					 * enable password
					 */
					session->is_enable = TRUE;
				}
			}
		}
	}

	if (check_normal == FALSE && check_enable == FALSE) {
		msg_info ("absent or incorrect password has been specified; source ip: %s",
				rspamd_inet_address_to_string_pretty (session->from_addr));
		ret = FALSE;
	}

end:
	if (query_args != NULL) {
		g_hash_table_unref (query_args);
	}

	if (!ret) {
		rspamd_controller_send_error (entry, 403, "Unauthorized");
	}

	return ret;
}

/* Command handlers */

/*
 * Auth command handler:
 * request: /auth
 * headers: Password
 * reply: json {"auth": "ok", "version": "0.5.2", "uptime": "some uptime", "error": "none"}
 */
static int
rspamd_controller_handle_auth (struct rspamd_http_connection_entry *conn_ent,
	struct rspamd_http_message *msg)
{
	struct rspamd_controller_session *session = conn_ent->ud;
	struct rspamd_stat *st;
	int64_t uptime;
	gulong data[5];
	ucl_object_t *obj;

	if (!rspamd_controller_check_password (conn_ent, session, msg, FALSE)) {
		return 0;
	}

	obj = ucl_object_typed_new (UCL_OBJECT);
	st = session->ctx->srv->stat;
	data[0] = st->actions_stat[METRIC_ACTION_NOACTION];
	data[1] = st->actions_stat[METRIC_ACTION_ADD_HEADER] +
		st->actions_stat[METRIC_ACTION_REWRITE_SUBJECT];
	data[2] = st->actions_stat[METRIC_ACTION_GREYLIST];
	data[3] = st->actions_stat[METRIC_ACTION_REJECT];
	data[4] = st->actions_stat[METRIC_ACTION_SOFT_REJECT];

	/* Get uptime */
	uptime = ev_time () - session->ctx->start_time;

	ucl_object_insert_key (obj, ucl_object_fromstring (
			RVERSION),			   "version",  0, false);
	ucl_object_insert_key (obj, ucl_object_fromstring (
			"ok"),				   "auth",	   0, false);
	ucl_object_insert_key (obj,	   ucl_object_fromint (
			uptime),			   "uptime",   0, false);
	ucl_object_insert_key (obj,	   ucl_object_fromint (
			data[0]),			   "clean",	   0, false);
	ucl_object_insert_key (obj,	   ucl_object_fromint (
			data[1]),			   "probable", 0, false);
	ucl_object_insert_key (obj,	   ucl_object_fromint (
			data[2]),			   "greylist", 0, false);
	ucl_object_insert_key (obj,	   ucl_object_fromint (
			data[3]),			   "reject",   0, false);
	ucl_object_insert_key (obj,	   ucl_object_fromint (
			data[4]),			   "soft_reject",   0, false);
	ucl_object_insert_key (obj,	   ucl_object_fromint (
			st->messages_scanned), "scanned",  0, false);
	ucl_object_insert_key (obj,	   ucl_object_fromint (
			st->messages_learned), "learned",  0, false);
	ucl_object_insert_key (obj, ucl_object_frombool (!session->is_enable),
			"read_only", 0, false);
	ucl_object_insert_key (obj, ucl_object_fromstring (session->ctx->cfg->checksum),
			"config_id", 0, false);

	rspamd_controller_send_ucl (conn_ent, obj);
	ucl_object_unref (obj);

	return 0;
}

/*
 * Symbols command handler:
 * request: /symbols
 * reply: json [{
 *  "name": "group_name",
 *  "symbols": [
 *      {
 *      "name": "name",
 *      "weight": 0.1,
 *      "description": "description of symbol"
 *      },
 *      {...}
 * },
 * {...}]
 */
static int
rspamd_controller_handle_symbols (struct rspamd_http_connection_entry *conn_ent,
	struct rspamd_http_message *msg)
{
	struct rspamd_controller_session *session = conn_ent->ud;
	GHashTableIter it, sit;
	struct rspamd_symbols_group *gr;
	struct rspamd_symbol *sym;
	ucl_object_t *obj, *top, *sym_obj, *group_symbols;
	gpointer k, v;

	if (!rspamd_controller_check_password (conn_ent, session, msg, FALSE)) {
		return 0;
	}

	top = ucl_object_typed_new (UCL_ARRAY);

	/* Go through all symbols groups in the default metric */
	g_hash_table_iter_init (&it, session->cfg->groups);

	while (g_hash_table_iter_next (&it, &k, &v)) {
		gr = v;
		obj = ucl_object_typed_new (UCL_OBJECT);
		ucl_object_insert_key (obj, ucl_object_fromstring (
				gr->name), "group", 0, false);
		/* Iterate through all symbols */

		g_hash_table_iter_init (&sit, gr->symbols);
		group_symbols = ucl_object_typed_new (UCL_ARRAY);

		while (g_hash_table_iter_next (&sit, &k, &v)) {
			gdouble tm = 0.0, freq = 0, freq_dev = 0;

			sym = v;
			sym_obj = ucl_object_typed_new (UCL_OBJECT);

			ucl_object_insert_key (sym_obj, ucl_object_fromstring (sym->name),
				"symbol", 0, false);
			ucl_object_insert_key (sym_obj,
				ucl_object_fromdouble (*sym->weight_ptr),
				"weight", 0, false);
			if (sym->description) {
				ucl_object_insert_key (sym_obj,
					ucl_object_fromstring (sym->description),
					"description", 0, false);
			}

			if (rspamd_symcache_stat_symbol (session->ctx->cfg->cache,
					sym->name, &freq, &freq_dev, &tm, NULL)) {
				ucl_object_insert_key (sym_obj,
						ucl_object_fromdouble (freq),
						"frequency", 0, false);
				ucl_object_insert_key (sym_obj,
						ucl_object_fromdouble (freq_dev),
						"frequency_stddev", 0, false);
				ucl_object_insert_key (sym_obj,
						ucl_object_fromdouble (tm),
						"time", 0, false);
			}

			ucl_array_append (group_symbols, sym_obj);
		}

		ucl_object_insert_key (obj, group_symbols, "rules", 0, false);
		ucl_array_append (top, obj);
	}

	rspamd_controller_send_ucl (conn_ent, top);
	ucl_object_unref (top);

	return 0;
}

/*
 * Actions command handler:
 * request: /actions
 * reply: json [{
 *  "action": "no action",
 *  "value": 1.1
 * },
 * {...}]
 */
static int
rspamd_controller_handle_actions (struct rspamd_http_connection_entry *conn_ent,
	struct rspamd_http_message *msg)
{
	struct rspamd_controller_session *session = conn_ent->ud;
	struct rspamd_action *act, *tmp;
	ucl_object_t *obj, *top;

	if (!rspamd_controller_check_password (conn_ent, session, msg, FALSE)) {
		return 0;
	}

	top = ucl_object_typed_new (UCL_ARRAY);

	HASH_ITER (hh, session->cfg->actions, act, tmp) {
		obj = ucl_object_typed_new (UCL_OBJECT);
		ucl_object_insert_key (obj,
				ucl_object_fromstring (act->name),
				"action", 0, false);
		ucl_object_insert_key (obj,
				ucl_object_fromdouble (act->threshold),
				"value", 0, false);
		ucl_array_append (top, obj);
	}

	rspamd_controller_send_ucl (conn_ent, top);
	ucl_object_unref (top);

	return 0;
}

static gboolean
rspamd_controller_can_edit_map (struct rspamd_map_backend *bk)
{
	gchar *fpath;

	if (access (bk->uri, W_OK) == 0) {
		return TRUE;
	}
	else if (access (bk->uri, R_OK) == -1 && errno == ENOENT) {
		fpath = g_path_get_dirname (bk->uri);

		if (fpath) {
			if (access (fpath, W_OK) == 0) {
				g_free (fpath);

				return TRUE;
			}

			g_free (fpath);
		}
	}

	return FALSE;
}

/*
 * Maps command handler:
 * request: /maps
 * headers: Password
 * reply: json [
 *      {
 *      "map": "name",
 *      "description": "description",
 *      "editable": true
 *      },
 *      {...}
 * ]
 */
static int
rspamd_controller_handle_maps (struct rspamd_http_connection_entry *conn_ent,
	struct rspamd_http_message *msg)
{
	struct rspamd_controller_session *session = conn_ent->ud;
	GList *cur;
	struct rspamd_map *map;
	struct rspamd_map_backend *bk;
	guint i;
	gboolean editable;
	ucl_object_t *obj, *top;

	if (!rspamd_controller_check_password (conn_ent, session, msg, FALSE)) {
		return 0;
	}

	top = ucl_object_typed_new (UCL_ARRAY);

	/* Iterate over all maps */
	cur = session->ctx->cfg->maps;
	while (cur) {
		map = cur->data;

		PTR_ARRAY_FOREACH (map->backends, i, bk) {

			if (bk->protocol == MAP_PROTO_FILE) {
				editable = rspamd_controller_can_edit_map (bk);

				if (!editable && access (bk->uri, R_OK) == -1) {
					/* Skip unreadable and non-existing maps */
					continue;
				}

				obj = ucl_object_typed_new (UCL_OBJECT);
				ucl_object_insert_key (obj,	   ucl_object_fromint (bk->id),
						"map", 0, false);
				if (map->description) {
					ucl_object_insert_key (obj, ucl_object_fromstring (map->description),
							"description", 0, false);
				}
				ucl_object_insert_key (obj, ucl_object_fromstring (bk->uri),
						"uri", 0, false);
				ucl_object_insert_key (obj,	  ucl_object_frombool (editable),
						"editable", 0, false);
				ucl_array_append (top, obj);
			}
		}
		cur = g_list_next (cur);
	}

	rspamd_controller_send_ucl (conn_ent, top);
	ucl_object_unref (top);

	return 0;
}

/*
 * Get map command handler:
 * request: /getmap
 * headers: Password, Map
 * reply: plain-text
 */
static int
rspamd_controller_handle_get_map (struct rspamd_http_connection_entry *conn_ent,
	struct rspamd_http_message *msg)
{
	struct rspamd_controller_session *session = conn_ent->ud;
	GList *cur;
	struct rspamd_map *map;
	struct rspamd_map_backend *bk = NULL;
	const rspamd_ftok_t *idstr;
	struct stat st;
	gint fd;
	gulong id, i;
	gboolean found = FALSE;
	struct rspamd_http_message *reply;

	if (!rspamd_controller_check_password (conn_ent, session, msg, FALSE)) {
		return 0;
	}

	idstr = rspamd_http_message_find_header (msg, "Map");

	if (idstr == NULL) {
		msg_info_session ("absent map id");
		rspamd_controller_send_error (conn_ent, 400, "Id header missing");
		return 0;
	}

	if (!rspamd_strtoul (idstr->begin, idstr->len, &id)) {
		msg_info_session ("invalid map id");
		rspamd_controller_send_error (conn_ent, 400, "Invalid map id");
		return 0;
	}

	/* Now let's be sure that we have map defined in configuration */
	cur = session->ctx->cfg->maps;
	while (cur && !found) {
		map = cur->data;

		PTR_ARRAY_FOREACH (map->backends, i, bk) {
			if (bk->id == id && bk->protocol == MAP_PROTO_FILE) {
				found = TRUE;
				break;
			}
		}

		cur = g_list_next (cur);
	}

	if (!found || bk == NULL) {
		msg_info_session ("map not found");
		rspamd_controller_send_error (conn_ent, 404, "Map not found");
		return 0;
	}

	if (stat (bk->uri, &st) == -1 || (fd = open (bk->uri, O_RDONLY)) == -1) {
		reply = rspamd_http_new_message (HTTP_RESPONSE);
		reply->date = time (NULL);
		reply->code = 200;
	}
	else {

		reply = rspamd_http_new_message (HTTP_RESPONSE);
		reply->date = time (NULL);
		reply->code = 200;

		if (st.st_size > 0) {
			if (!rspamd_http_message_set_body_from_fd (reply, fd)) {
				close (fd);
				rspamd_http_message_unref (reply);
				msg_err_session ("cannot read map %s: %s", bk->uri, strerror (errno));
				rspamd_controller_send_error (conn_ent, 500, "Map read error");
				return 0;
			}
		}
		else {
			rspamd_fstring_t *empty_body = rspamd_fstring_new_init ("", 0);
			rspamd_http_message_set_body_from_fstring_steal (reply, empty_body);
		}

		close (fd);
	}

	rspamd_http_connection_reset (conn_ent->conn);
	rspamd_http_router_insert_headers (conn_ent->rt, reply);
	rspamd_http_connection_write_message (conn_ent->conn, reply, NULL,
			"text/plain", conn_ent,
			conn_ent->rt->timeout);
	conn_ent->is_reply = TRUE;

	return 0;
}

static ucl_object_t *
rspamd_controller_pie_element (enum rspamd_action_type action,
		const char *label, gdouble data)
{
	ucl_object_t *res = ucl_object_typed_new (UCL_OBJECT);
	const char *colors[METRIC_ACTION_MAX] = {
		[METRIC_ACTION_REJECT] = "#FF0000",
		[METRIC_ACTION_SOFT_REJECT] = "#cc9966",
		[METRIC_ACTION_REWRITE_SUBJECT] = "#ff6600",
		[METRIC_ACTION_ADD_HEADER] = "#FFD700",
		[METRIC_ACTION_GREYLIST] = "#436EEE",
		[METRIC_ACTION_NOACTION] = "#66cc00"
	};

	ucl_object_insert_key (res, ucl_object_fromstring (colors[action]),
			"color", 0, false);
	ucl_object_insert_key (res, ucl_object_fromstring (label), "label", 0, false);
	ucl_object_insert_key (res, ucl_object_fromdouble (data), "data", 0, false);
	ucl_object_insert_key (res, ucl_object_fromdouble (data), "value", 0, false);

	return res;
}

/*
 * Pie chart command handler:
 * request: /pie
 * headers: Password
 * reply: json [
 *      { label: "Foo", data: 11 },
 *      { label: "Bar", data: 20 },
 *      {...}
 * ]
 */
static int
rspamd_controller_handle_pie_chart (
	struct rspamd_http_connection_entry *conn_ent,
	struct rspamd_http_message *msg)
{
	struct rspamd_controller_session *session = conn_ent->ud;
	struct rspamd_controller_worker_ctx *ctx;
	gdouble data[5], total;
	ucl_object_t *top;

	ctx = session->ctx;

	if (!rspamd_controller_check_password (conn_ent, session, msg, FALSE)) {
		return 0;
	}

	top = ucl_object_typed_new (UCL_ARRAY);
	total = ctx->srv->stat->messages_scanned;
	if (total != 0) {

		data[0] = ctx->srv->stat->actions_stat[METRIC_ACTION_NOACTION];
		data[1] = ctx->srv->stat->actions_stat[METRIC_ACTION_SOFT_REJECT];
		data[2] = (ctx->srv->stat->actions_stat[METRIC_ACTION_ADD_HEADER] +
			ctx->srv->stat->actions_stat[METRIC_ACTION_REWRITE_SUBJECT]);
		data[3] = ctx->srv->stat->actions_stat[METRIC_ACTION_GREYLIST];
		data[4] = ctx->srv->stat->actions_stat[METRIC_ACTION_REJECT];
	}
	else {
		memset (data, 0, sizeof (data));
	}
	ucl_array_append (top, rspamd_controller_pie_element (
			METRIC_ACTION_NOACTION, "Clean", data[0]));
	ucl_array_append (top, rspamd_controller_pie_element (
			METRIC_ACTION_SOFT_REJECT, "Temporarily rejected", data[1]));
	ucl_array_append (top, rspamd_controller_pie_element (
			METRIC_ACTION_ADD_HEADER, "Probable spam", data[2]));
	ucl_array_append (top, rspamd_controller_pie_element (
			METRIC_ACTION_GREYLIST, "Greylisted", data[3]));
	ucl_array_append (top, rspamd_controller_pie_element (
			METRIC_ACTION_REJECT, "Rejected", data[4]));

	rspamd_controller_send_ucl (conn_ent, top);
	ucl_object_unref (top);

	return 0;
}

void
rspamd_controller_graph_point (gulong t, gulong step,
		struct rspamd_rrd_query_result* rrd_result,
		gdouble *acc,
		ucl_object_t **elt)
{
	guint nan_cnt;
	gdouble sum = 0.0, yval;
	ucl_object_t* data_elt;
	guint i, j;

	for (i = 0; i < rrd_result->ds_count; i++) {
		sum = 0.0;
		nan_cnt = 0;
		data_elt = ucl_object_typed_new (UCL_OBJECT);
		ucl_object_insert_key (data_elt, ucl_object_fromint (t), "x", 1, false);

		for (j = 0; j < step; j++) {
			yval = acc[i + j * rrd_result->ds_count];
			if (!isfinite (yval)) {
				nan_cnt++;
			}
			else {
				sum += yval;
			}
		}
		if (nan_cnt == step) {
			ucl_object_insert_key (data_elt, ucl_object_typed_new (UCL_NULL),
					"y", 1, false);
		}
		else {
			ucl_object_insert_key (data_elt,
					ucl_object_fromdouble (sum / (gdouble) step), "y", 1,
					false);
		}
		ucl_array_append (elt[i], data_elt);
	}
}

/*
 * Graph command handler:
 * request: /graph?type=<day|week|month|year>
 * headers: Password
 * reply: json [
 *      { label: "Foo", data: 11 },
 *      { label: "Bar", data: 20 },
 *      {...}
 * ]
 */
static int
rspamd_controller_handle_graph (
		struct rspamd_http_connection_entry *conn_ent,
		struct rspamd_http_message *msg)
{
	GHashTable *query;
	struct rspamd_controller_session *session = conn_ent->ud;
	struct rspamd_controller_worker_ctx *ctx;
	rspamd_ftok_t srch, *value;
	struct rspamd_rrd_query_result *rrd_result;
	gulong i, k, start_row, cnt, t, ts, step;
	gdouble *acc;
	ucl_object_t *res, *elt[METRIC_ACTION_MAX];
	enum {
		rra_day = 0,
		rra_week,
		rra_month,
		rra_year,
		rra_invalid
	} rra_num = rra_invalid;
	/* How many points are we going to send to display */
	static const guint desired_points = 500;

	ctx = session->ctx;

	if (!rspamd_controller_check_password (conn_ent, session, msg, FALSE)) {
		return 0;
	}

	if (ctx->rrd == NULL) {
		msg_err_session ("no rrd configured");
		rspamd_controller_send_error (conn_ent, 404, "No rrd configured for graphs");

		return 0;
	}

	query = rspamd_http_message_parse_query (msg);
	srch.begin = (gchar *)"type";
	srch.len = 4;

	if (query == NULL || (value = g_hash_table_lookup (query, &srch)) == NULL) {
		msg_err_session ("absent graph type query");
		rspamd_controller_send_error (conn_ent, 400, "Absent graph type");

		if (query) {
			g_hash_table_unref (query);
		}

		return 0;
	}

	if (value->len == 3 && rspamd_lc_cmp (value->begin, "day", value->len) == 0) {
		rra_num = rra_day;
	}
	else if (value->len == 4 && rspamd_lc_cmp (value->begin, "week", value->len) == 0) {
		rra_num = rra_week;
	}
	else if (value->len == 5 && rspamd_lc_cmp (value->begin, "month", value->len) == 0) {
		rra_num = rra_month;
	}
	else if (value->len == 4 && rspamd_lc_cmp (value->begin, "year", value->len) == 0) {
		rra_num = rra_year;
	}

	g_hash_table_unref (query);

	if (rra_num == rra_invalid) {
		msg_err_session ("invalid graph type query");
		rspamd_controller_send_error (conn_ent, 400, "Invalid graph type");

		return 0;
	}

	rrd_result = rspamd_rrd_query (ctx->rrd, rra_num);

	if (rrd_result == NULL) {
		msg_err_session ("cannot query rrd");
		rspamd_controller_send_error (conn_ent, 500, "Cannot query rrd");

		return 0;
	}

	g_assert (rrd_result->ds_count == G_N_ELEMENTS (elt));

	res = ucl_object_typed_new (UCL_ARRAY);
	/* How much full updates happened since the last update */
	ts = rrd_result->last_update / rrd_result->pdp_per_cdp - rrd_result->rra_rows;

	for (i = 0; i < rrd_result->ds_count; i ++) {
		elt[i] = ucl_object_typed_new (UCL_ARRAY);
	}

	start_row = rrd_result->cur_row == rrd_result->rra_rows - 1 ?
				0 : rrd_result->cur_row;
	t = ts * rrd_result->pdp_per_cdp;
	k = 0;

	/* Create window */
	step = ceil (((gdouble)rrd_result->rra_rows) / desired_points);
	g_assert (step >= 1);
	acc = g_malloc0 (sizeof (double) * rrd_result->ds_count * step);

	for (i = start_row, cnt = 0; cnt < rrd_result->rra_rows;
			cnt ++) {

		memcpy (&acc[k * rrd_result->ds_count],
				&rrd_result->data[i * rrd_result->ds_count],
				sizeof (gdouble) * rrd_result->ds_count);

		if (k < step - 1) {
			k ++;
		}
		else {
			t = ts * rrd_result->pdp_per_cdp;

			/* Need a fresh point */
			rspamd_controller_graph_point (t, step, rrd_result, acc, elt);
			k = 0;
		}

		if (i == rrd_result->rra_rows - 1) {
			i = 0;
		}
		else {
			i ++;
		}

		ts ++;
	}

	if (k > 0) {
		rspamd_controller_graph_point (t, k, rrd_result, acc, elt);
	}

	for (i = 0; i < rrd_result->ds_count; i++) {
		ucl_array_append (res, elt[i]);
	}

	rspamd_controller_send_ucl (conn_ent, res);
	ucl_object_unref (res);
	g_free (acc);

	return 0;
}

static void
rspamd_controller_handle_legacy_history (
		struct rspamd_controller_session *session,
		struct rspamd_controller_worker_ctx *ctx,
		struct rspamd_http_connection_entry *conn_ent,
		struct rspamd_http_message *msg)
{
	struct roll_history_row *row, *copied_rows;
	guint i, rows_proc, row_num;
	struct tm tm;
	gchar timebuf[32], **syms;
	ucl_object_t *top, *obj;

	top = ucl_object_typed_new (UCL_ARRAY);

	/* Set lock on history */
	copied_rows = g_malloc (sizeof (*copied_rows) * ctx->srv->history->nrows);
	memcpy (copied_rows, ctx->srv->history->rows,
			sizeof (*copied_rows) * ctx->srv->history->nrows);

	/* Go through all rows */
	row_num = ctx->srv->history->cur_row;

	for (i = 0, rows_proc = 0; i < ctx->srv->history->nrows; i++, row_num++) {
		if (row_num == ctx->srv->history->nrows) {
			row_num = 0;
		}
		row = &copied_rows[row_num];
		/* Get only completed rows */
		if (row->completed) {
			rspamd_localtime (row->timestamp, &tm);
			strftime (timebuf, sizeof (timebuf) - 1, "%Y-%m-%d %H:%M:%S", &tm);
			obj = ucl_object_typed_new (UCL_OBJECT);
			ucl_object_insert_key (obj, ucl_object_fromstring (
					timebuf),		  "time", 0, false);
			ucl_object_insert_key (obj, ucl_object_fromint (
					row->timestamp), "unix_time", 0, false);
			ucl_object_insert_key (obj, ucl_object_fromstring (
					row->message_id), "id",	  0, false);
			ucl_object_insert_key (obj, ucl_object_fromstring (row->from_addr),
					"ip", 0, false);
			ucl_object_insert_key (obj,
					ucl_object_fromstring (rspamd_action_to_str (
							row->action)), "action", 0, false);

			if (!isnan (row->score)) {
				ucl_object_insert_key (obj, ucl_object_fromdouble (
						row->score),		  "score",			0, false);
			}
			else {
				ucl_object_insert_key (obj,
						ucl_object_fromdouble (0.0), "score", 0, false);
			}

			if (!isnan (row->required_score)) {
				ucl_object_insert_key (obj,
						ucl_object_fromdouble (
								row->required_score), "required_score", 0, false);
			}
			else {
				ucl_object_insert_key (obj,
						ucl_object_fromdouble (0.0), "required_score", 0, false);
			}

			syms = g_strsplit_set (row->symbols, ", ", -1);

			if (syms) {
				guint nelts = g_strv_length (syms);
				ucl_object_t *syms_obj = ucl_object_typed_new (UCL_OBJECT);
				ucl_object_reserve (syms_obj, nelts);

				for (guint j = 0; j < nelts; j++) {
					g_strstrip (syms[j]);

					if (strlen (syms[j]) == 0) {
						/* Empty garbadge */
						continue;
					}

					ucl_object_t *cur = ucl_object_typed_new (UCL_OBJECT);

					ucl_object_insert_key (cur, ucl_object_fromdouble (0.0),
							"score", 0, false);
					ucl_object_insert_key (syms_obj, cur, syms[j], 0, true);
				}

				ucl_object_insert_key (obj, syms_obj, "symbols", 0, false);
				g_strfreev (syms);
			}

			ucl_object_insert_key (obj, ucl_object_fromint (row->len),
					"size", 0, false);
			ucl_object_insert_key (obj,
					ucl_object_fromdouble (row->scan_time),
					"scan_time", 0, false);

			if (row->user[0] != '\0') {
				ucl_object_insert_key (obj, ucl_object_fromstring (row->user),
						"user", 0, false);
			}
			if (row->from_addr[0] != '\0') {
				ucl_object_insert_key (obj, ucl_object_fromstring (
						row->from_addr), "from", 0, false);
			}
			ucl_array_append (top, obj);
			rows_proc++;
		}
	}

	rspamd_controller_send_ucl (conn_ent, top);
	ucl_object_unref (top);
	g_free (copied_rows);
}

static gboolean
rspamd_controller_history_lua_fin_task (void *ud)
{
	return TRUE;
}

static void
rspamd_controller_handle_lua_history (lua_State *L,
		struct rspamd_controller_session *session,
		struct rspamd_controller_worker_ctx *ctx,
		struct rspamd_http_connection_entry *conn_ent,
		struct rspamd_http_message *msg,
		gboolean reset)
{
	struct rspamd_task *task, **ptask;
	struct rspamd_http_connection_entry **pconn_ent;
	GHashTable *params;
	rspamd_ftok_t srch, *found;
	glong from = 0, to = -1;

	params = rspamd_http_message_parse_query (msg);

	if (params) {
		/* Check from and to */
		RSPAMD_FTOK_ASSIGN (&srch, "from");
		found = g_hash_table_lookup (params, &srch);

		if (found) {
			rspamd_strtol (found->begin, found->len, &from);
		}
		RSPAMD_FTOK_ASSIGN (&srch, "to");
		found = g_hash_table_lookup (params, &srch);

		if (found) {
			rspamd_strtol (found->begin, found->len, &to);
		}

		g_hash_table_unref (params);
	}

	lua_getglobal (L, "rspamd_plugins");

	if (lua_istable (L, -1)) {
		lua_pushstring (L, "history");
		lua_gettable (L, -2);

		if (lua_istable (L, -1)) {
			lua_pushstring (L, "handler");
			lua_gettable (L, -2);

			if (lua_isfunction (L, -1)) {
				task = rspamd_task_new (session->ctx->worker, session->cfg,
						session->pool, ctx->lang_det, ctx->event_loop, FALSE);

				task->resolver = ctx->resolver;
				task->s = rspamd_session_create (session->pool,
						rspamd_controller_history_lua_fin_task,
						NULL,
						(event_finalizer_t )rspamd_task_free,
						task);
				task->fin_arg = conn_ent;

				ptask = lua_newuserdata (L, sizeof (*ptask));
				*ptask = task;
				rspamd_lua_setclass (L, "rspamd{task}", -1);
				pconn_ent = lua_newuserdata (L, sizeof (*pconn_ent));
				*pconn_ent = conn_ent;
				rspamd_lua_setclass (L, "rspamd{csession}", -1);
				lua_pushinteger (L, from);
				lua_pushinteger (L, to);
				lua_pushboolean (L, reset);

				if (lua_pcall (L, 5, 0, 0) != 0) {
					msg_err_session ("call to history function failed: %s",
							lua_tostring (L, -1));
					lua_settop (L, 0);
					rspamd_task_free (task);

					goto err;
				}

				task->http_conn = rspamd_http_connection_ref (conn_ent->conn);;
				task->sock = -1;
				session->task = task;

				rspamd_session_pending (task->s);
			}
			else {
				msg_err_session ("rspamd_plugins.history.handler is not a function");
				lua_settop (L, 0);
				goto err;
			}
		}
		else {
			msg_err_session ("rspamd_plugins.history is not a table");
			lua_settop (L, 0);
			goto err;
		}
	}
	else {
		msg_err_session ("rspamd_plugins is absent or has incorrect type");
		lua_settop (L, 0);
		goto err;
	}

	lua_settop (L, 0);

	return;
err:
	rspamd_controller_send_error (conn_ent, 500, "Internal error");
}

/*
 * Healthy command handler:
 * request: /healthy
 * headers: Password
 * reply: json {"success":true}
 */
static int
rspamd_controller_handle_healthy (struct rspamd_http_connection_entry *conn_ent,
        struct rspamd_http_message *msg)
{
    struct rspamd_controller_session *session = conn_ent->ud;

    if (!rspamd_controller_check_password (conn_ent, session, msg, FALSE)) {
        return 0;
    }

    rspamd_controller_send_string (conn_ent, "{\"success\":true}");
    return 0;
}

/*
 * Ready command handler:
 * request: /ready
 * headers: Password
 * reply: json {"success":true} or {"error":"error message"}
 */
static int
rspamd_controller_handle_ready (struct rspamd_http_connection_entry *conn_ent,
        struct rspamd_http_message *msg)
{
    struct rspamd_controller_session *session = conn_ent->ud;

    if (!rspamd_controller_check_password (conn_ent, session, msg, FALSE)) {
        return 0;
    }

    rspamd_controller_send_string (conn_ent, "{\"success\":true}");
    return 0;
}

/*
 * History command handler:
 * request: /history
 * headers: Password
 * reply: json [
 *      { label: "Foo", data: 11 },
 *      { label: "Bar", data: 20 },
 *      {...}
 * ]
 */
static int
rspamd_controller_handle_history (struct rspamd_http_connection_entry *conn_ent,
	struct rspamd_http_message *msg)
{
	struct rspamd_controller_session *session = conn_ent->ud;
	struct rspamd_controller_worker_ctx *ctx;
	lua_State *L;
	ctx = session->ctx;

	if (!rspamd_controller_check_password (conn_ent, session, msg, FALSE)) {
		return 0;
	}

	L = ctx->cfg->lua_state;

	if (!ctx->srv->history->disabled) {
		rspamd_controller_handle_legacy_history (session, ctx, conn_ent, msg);
	}
	else {
		rspamd_controller_handle_lua_history (L, session, ctx, conn_ent, msg,
				FALSE);
	}

	return 0;
}

/*
 * Errors command handler:
 * request: /errors
 * headers: Password
 * reply: json [
 *      { ts: 100500, type: normal, pid: 100, module: lua, message: bad things },
 *      {...}
 * ]
 */
static int
rspamd_controller_handle_errors (struct rspamd_http_connection_entry *conn_ent,
	struct rspamd_http_message *msg)
{
	struct rspamd_controller_session *session = conn_ent->ud;
	struct rspamd_controller_worker_ctx *ctx;
	ucl_object_t *top;

	ctx = session->ctx;

	if (!rspamd_controller_check_password (conn_ent, session, msg, TRUE)) {
		return 0;
	}

	top = rspamd_log_errorbuf_export (ctx->worker->srv->logger);
	rspamd_controller_send_ucl (conn_ent, top);
	ucl_object_unref (top);

	return 0;
}

/*
 * Neighbours command handler:
 * request: /neighbours
 * headers: Password
 * reply: json {name: {url: "http://...", host: "host"}}
 */
static int
rspamd_controller_handle_neighbours (struct rspamd_http_connection_entry *conn_ent,
	struct rspamd_http_message *msg)
{
	struct rspamd_controller_session *session = conn_ent->ud;
	struct rspamd_controller_worker_ctx *ctx;

	ctx = session->ctx;

	if (!rspamd_controller_check_password (conn_ent, session, msg, FALSE)) {
		return 0;
	}

	rspamd_controller_send_ucl (conn_ent, ctx->cfg->neighbours);

	return 0;
}


static int
rspamd_controller_handle_history_reset (struct rspamd_http_connection_entry *conn_ent,
		struct rspamd_http_message *msg)
{
	struct rspamd_controller_session *session = conn_ent->ud;
	struct rspamd_controller_worker_ctx *ctx;
	struct roll_history_row *row;
	guint completed_rows, i, t;
	lua_State *L;

	ctx = session->ctx;
	L = ctx->cfg->lua_state;

	if (!rspamd_controller_check_password (conn_ent, session, msg, TRUE)) {
		return 0;
	}

	if (!ctx->srv->history->disabled) {
		/* Clean from start to the current row */
		completed_rows = g_atomic_int_get (&ctx->srv->history->cur_row);

		completed_rows = MIN (completed_rows, ctx->srv->history->nrows - 1);

		for (i = 0; i <= completed_rows; i ++) {
			t = g_atomic_int_get (&ctx->srv->history->cur_row);

			/* We somehow come to the race condition */
			if (i > t) {
				break;
			}

			row = &ctx->srv->history->rows[i];
			memset (row, 0, sizeof (*row));
		}

		msg_info_session ("<%s> cleared %d entries from history",
				rspamd_inet_address_to_string (session->from_addr),
				completed_rows);
		rspamd_controller_send_string (conn_ent, "{\"success\":true}");
	}
	else {
		rspamd_controller_handle_lua_history (L, session, ctx, conn_ent, msg,
				TRUE);
	}

	return 0;
}

static gboolean
rspamd_controller_lua_fin_task (void *ud)
{
	struct rspamd_task *task = ud;
	struct rspamd_http_connection_entry *conn_ent;

	conn_ent = task->fin_arg;

	if (task->err != NULL) {
		rspamd_controller_send_error (conn_ent, task->err->code, "%s",
				task->err->message);
	}

	return TRUE;
}

static int
rspamd_controller_handle_lua (struct rspamd_http_connection_entry *conn_ent,
		struct rspamd_http_message *msg)
{
	struct rspamd_controller_session *session = conn_ent->ud;
	struct rspamd_task *task, **ptask;
	struct rspamd_http_connection_entry **pconn;
	struct rspamd_controller_worker_ctx *ctx;
	gchar filebuf[PATH_MAX], realbuf[PATH_MAX];
	struct http_parser_url u;
	rspamd_ftok_t lookup;
	struct stat st;
	lua_State *L;

	if (!rspamd_controller_check_password (conn_ent, session, msg, TRUE)) {
		return 0;
	}

	ctx = session->ctx;
	L = ctx->cfg->lua_state;

	/* Find lua script */
	if (msg->url != NULL && msg->url->len != 0) {

		http_parser_parse_url (RSPAMD_FSTRING_DATA (msg->url),
				RSPAMD_FSTRING_LEN (msg->url), TRUE, &u);

		if (u.field_set & (1 << UF_PATH)) {
			lookup.begin = RSPAMD_FSTRING_DATA (msg->url) +
					u.field_data[UF_PATH].off;
			lookup.len = u.field_data[UF_PATH].len;
		}
		else {
			lookup.begin = RSPAMD_FSTRING_DATA (msg->url);
			lookup.len = RSPAMD_FSTRING_LEN (msg->url);
		}

		rspamd_snprintf (filebuf, sizeof (filebuf), "%s%c%T",
				ctx->static_files_dir, G_DIR_SEPARATOR, &lookup);

		if (realpath (filebuf, realbuf) == NULL ||
				lstat (realbuf, &st) == -1) {
			rspamd_controller_send_error (conn_ent, 404, "Cannot find path: %s",
					strerror (errno));

			return 0;
		}

		/* TODO: add caching here, should be trivial */
		/* Now we load and execute the code fragment, which should return a function */
		if (luaL_loadfile (L, realbuf) != 0) {
			rspamd_controller_send_error (conn_ent, 500, "Cannot load path: %s",
					lua_tostring (L, -1));
			lua_settop (L, 0);

			return 0;
		}

		if (lua_pcall (L, 0, 1, 0) != 0) {
			rspamd_controller_send_error (conn_ent, 501, "Cannot run path: %s",
					lua_tostring (L, -1));
			lua_settop (L, 0);

			return 0;
		}

		if (lua_type (L, -1) != LUA_TFUNCTION) {
			rspamd_controller_send_error (conn_ent, 502, "Bad return type: %s",
					lua_typename (L, lua_type (L, -1)));
			lua_settop (L, 0);

			return 0;
		}

	}
	else {
		rspamd_controller_send_error (conn_ent, 404, "Empty path is not permitted");

		return 0;
	}

	task = rspamd_task_new (session->ctx->worker, session->cfg, session->pool,
			ctx->lang_det, ctx->event_loop, FALSE);

	task->resolver = ctx->resolver;
	task->s = rspamd_session_create (session->pool,
			rspamd_controller_lua_fin_task,
			NULL,
			(event_finalizer_t )rspamd_task_free,
			task);
	task->fin_arg = conn_ent;
	task->http_conn = rspamd_http_connection_ref (conn_ent->conn);;
	task->sock = -1;
	session->task = task;

	if (msg->body_buf.len > 0) {
		if (!rspamd_task_load_message (task, msg, msg->body_buf.begin, msg->body_buf.len)) {
			rspamd_controller_send_error (conn_ent, task->err->code, "%s",
					task->err->message);
			return 0;
		}
	}

	ptask = lua_newuserdata (L, sizeof (*ptask));
	rspamd_lua_setclass (L, "rspamd{task}", -1);
	*ptask = task;

	pconn = lua_newuserdata (L, sizeof (*pconn));
	rspamd_lua_setclass (L, "rspamd{csession}", -1);
	*pconn = conn_ent;

	if (lua_pcall (L, 2, 0, 0) != 0) {
		rspamd_controller_send_error (conn_ent, 503, "Cannot run callback: %s",
				lua_tostring (L, -1));
		lua_settop (L, 0);

		return 0;
	}

	rspamd_session_pending (task->s);

	return 0;
}

static gboolean
rspamd_controller_learn_fin_task (void *ud)
{
	struct rspamd_task *task = ud;
	struct rspamd_controller_session *session;
	struct rspamd_http_connection_entry *conn_ent;

	conn_ent = task->fin_arg;
	session = conn_ent->ud;

	if (task->err != NULL) {
		msg_info_session ("cannot learn <%s>: %e",
				MESSAGE_FIELD (task, message_id), task->err);
		rspamd_controller_send_error (conn_ent, task->err->code, "%s",
				task->err->message);

		return TRUE;
	}

	if (RSPAMD_TASK_IS_PROCESSED (task)) {
		/* Successful learn */
		msg_info_task ("<%s> learned message as %s: %s",
				rspamd_inet_address_to_string (session->from_addr),
				session->is_spam ? "spam" : "ham",
				MESSAGE_FIELD (task, message_id));
		rspamd_controller_send_string (conn_ent, "{\"success\":true}");
		return TRUE;
	}

	if (!rspamd_task_process (task, RSPAMD_TASK_PROCESS_LEARN)) {
		msg_info_task ("cannot learn <%s>: %e",
				MESSAGE_FIELD (task, message_id), task->err);

		if (task->err) {
			rspamd_controller_send_error (conn_ent, task->err->code, "%s",
					task->err->message);
		}
		else {
			rspamd_controller_send_error (conn_ent, 500,
								"Internal error");
		}
	}

	if (RSPAMD_TASK_IS_PROCESSED (task)) {
		if (task->err) {
			rspamd_controller_send_error (conn_ent, task->err->code, "%s",
					task->err->message);
		}
		else {
			msg_info_task ("<%s> learned message as %s: %s",
					rspamd_inet_address_to_string (session->from_addr),
					session->is_spam ? "spam" : "ham",
					MESSAGE_FIELD (task, message_id));
			rspamd_controller_send_string (conn_ent, "{\"success\":true}");
		}

		return TRUE;
	}

	/* One more iteration */
	return FALSE;
}

static void
rspamd_controller_scan_reply (struct rspamd_task *task)
{
	struct rspamd_http_message *msg;
	struct rspamd_http_connection_entry *conn_ent;

	conn_ent = task->fin_arg;
	msg = rspamd_http_new_message (HTTP_RESPONSE);
	msg->date = time (NULL);
	msg->code = 200;
	rspamd_protocol_http_reply (msg, task, NULL);
	rspamd_http_connection_reset (conn_ent->conn);
	rspamd_http_router_insert_headers (conn_ent->rt, msg);
	rspamd_http_connection_write_message (conn_ent->conn, msg, NULL,
			"application/json", conn_ent, conn_ent->rt->timeout);
	conn_ent->is_reply = TRUE;
}

static gboolean
rspamd_controller_check_fin_task (void *ud)
{
	struct rspamd_task *task = ud;
	struct rspamd_http_connection_entry *conn_ent;

	msg_debug_task ("finish task");
	conn_ent = task->fin_arg;

	if (task->err) {
		msg_info_task ("cannot check <%s>: %e",
				MESSAGE_FIELD_CHECK (task, message_id), task->err);
		rspamd_controller_send_error (conn_ent, task->err->code, "%s",
				task->err->message);
		return TRUE;
	}

	if (RSPAMD_TASK_IS_PROCESSED (task)) {
		rspamd_controller_scan_reply (task);
		return TRUE;
	}

	if (!rspamd_task_process (task, RSPAMD_TASK_PROCESS_ALL)) {
		rspamd_controller_scan_reply (task);
		return TRUE;
	}

	if (RSPAMD_TASK_IS_PROCESSED (task)) {
		rspamd_controller_scan_reply (task);
		return TRUE;
	}

	/* One more iteration */
	return FALSE;
}

static int
rspamd_controller_handle_learn_common (
	struct rspamd_http_connection_entry *conn_ent,
	struct rspamd_http_message *msg,
	gboolean is_spam)
{
	struct rspamd_controller_session *session = conn_ent->ud;
	struct rspamd_controller_worker_ctx *ctx;
	struct rspamd_task *task;
	const rspamd_ftok_t *cl_header;

	ctx = session->ctx;

	if (!rspamd_controller_check_password (conn_ent, session, msg, TRUE)) {
		return 0;
	}

	if (rspamd_http_message_get_body (msg, NULL) == NULL) {
		msg_err_session ("got zero length body, cannot continue");
		rspamd_controller_send_error (conn_ent,
			400,
			"Empty body is not permitted");
		return 0;
	}

	task = rspamd_task_new (session->ctx->worker, session->cfg, session->pool,
			session->ctx->lang_det, ctx->event_loop, FALSE);

	task->resolver = ctx->resolver;
	task->s = rspamd_session_create (session->pool,
			rspamd_controller_learn_fin_task,
			NULL,
			(event_finalizer_t )rspamd_task_free,
			task);
	task->fin_arg = conn_ent;
	task->http_conn = rspamd_http_connection_ref (conn_ent->conn);;
	task->sock = -1;
	session->task = task;

	cl_header = rspamd_http_message_find_header (msg, "classifier");
	if (cl_header) {
		session->classifier = rspamd_mempool_ftokdup (session->pool, cl_header);
	}
	else {
		session->classifier = NULL;
	}

	if (!rspamd_task_load_message (task, msg, msg->body_buf.begin, msg->body_buf.len)) {
		goto end;
	}

	rspamd_learn_task_spam (task, is_spam, session->classifier, NULL);

	if (!rspamd_task_process (task, RSPAMD_TASK_PROCESS_LEARN)) {
		msg_warn_session ("<%s> message cannot be processed",
				MESSAGE_FIELD (task, message_id));
		goto end;
	}

end:
	session->is_spam = is_spam;
	rspamd_session_pending (task->s);

	return 0;
}

/*
 * Learn spam command handler:
 * request: /learnspam
 * headers: Password
 * input: plaintext data
 * reply: json {"success":true} or {"error":"error message"}
 */
static int
rspamd_controller_handle_learnspam (
	struct rspamd_http_connection_entry *conn_ent,
	struct rspamd_http_message *msg)
{
	return rspamd_controller_handle_learn_common (conn_ent, msg, TRUE);
}
/*
 * Learn ham command handler:
 * request: /learnham
 * headers: Password
 * input: plaintext data
 * reply: json {"success":true} or {"error":"error message"}
 */
static int
rspamd_controller_handle_learnham (
	struct rspamd_http_connection_entry *conn_ent,
	struct rspamd_http_message *msg)
{
	return rspamd_controller_handle_learn_common (conn_ent, msg, FALSE);
}

/*
 * Scan command handler:
 * request: /scan
 * headers: Password
 * input: plaintext data
 * reply: json {scan data} or {"error":"error message"}
 */
static int
rspamd_controller_handle_scan (struct rspamd_http_connection_entry *conn_ent,
	struct rspamd_http_message *msg)
{
	struct rspamd_controller_session *session = conn_ent->ud;
	struct rspamd_controller_worker_ctx *ctx;
	struct rspamd_task *task;

	ctx = session->ctx;

	if (!rspamd_controller_check_password (conn_ent, session, msg, FALSE)) {
		return 0;
	}

	task = rspamd_task_new (session->ctx->worker, session->cfg, session->pool,
			ctx->lang_det, ctx->event_loop, FALSE);

	task->resolver = ctx->resolver;
	task->s = rspamd_session_create (session->pool,
			rspamd_controller_check_fin_task,
			NULL,
			(event_finalizer_t )rspamd_task_free,
			task);
	task->fin_arg = conn_ent;
	task->http_conn = rspamd_http_connection_ref (conn_ent->conn);
	task->sock = conn_ent->conn->fd;
	task->flags |= RSPAMD_TASK_FLAG_MIME;
	task->resolver = ctx->resolver;

	if (!rspamd_protocol_handle_request (task, msg)) {
		goto end;
	}

	if (!rspamd_task_load_message (task, msg, msg->body_buf.begin, msg->body_buf.len)) {
		goto end;
	}

	if (!rspamd_task_process (task, RSPAMD_TASK_PROCESS_ALL)) {
		goto end;
	}

	if (ctx->task_timeout > 0.0) {
		task->timeout_ev.data = task;
		ev_timer_init (&task->timeout_ev, rspamd_task_timeout,
				ctx->task_timeout, ctx->task_timeout);
		ev_timer_start (task->event_loop, &task->timeout_ev);
		ev_set_priority (&task->timeout_ev, EV_MAXPRI);
	}

end:
	session->task = task;
	rspamd_session_pending (task->s);

	return 0;
}

/*
 * Save actions command handler:
 * request: /saveactions
 * headers: Password
 * input: json array [<spam>,<probable spam>,<greylist>]
 * reply: json {"success":true} or {"error":"error message"}
 */
static int
rspamd_controller_handle_saveactions (
	struct rspamd_http_connection_entry *conn_ent,
	struct rspamd_http_message *msg)
{
	struct rspamd_controller_session *session = conn_ent->ud;
	struct ucl_parser *parser;
	ucl_object_t *obj;
	const ucl_object_t *cur;
	struct rspamd_controller_worker_ctx *ctx;
	const gchar *error;
	gdouble score;
	gint i, added = 0;
	enum rspamd_action_type act;
	ucl_object_iter_t it = NULL;

	ctx = session->ctx;

	if (!rspamd_controller_check_password (conn_ent, session, msg, TRUE)) {
		return 0;
	}

	if (rspamd_http_message_get_body (msg, NULL) == NULL) {
		msg_err_session ("got zero length body, cannot continue");
		rspamd_controller_send_error (conn_ent,
			400,
			"Empty body is not permitted");
		return 0;
	}

	parser = ucl_parser_new (0);
	if (!ucl_parser_add_chunk (parser, msg->body_buf.begin, msg->body_buf.len)) {
		if ((error = ucl_parser_get_error (parser)) != NULL) {
			msg_err_session ("cannot parse input: %s", error);
			rspamd_controller_send_error (conn_ent, 400, "Cannot parse input");
			ucl_parser_free (parser);
			return 0;
		}

		msg_err_session ("cannot parse input: unknown error");
		rspamd_controller_send_error (conn_ent, 400, "Cannot parse input");
		ucl_parser_free (parser);
		return 0;
	}

	obj = ucl_parser_get_object (parser);
	ucl_parser_free (parser);

	if (obj->type != UCL_ARRAY || obj->len != 4) {
		msg_err_session ("input is not an array of 4 elements");
		rspamd_controller_send_error (conn_ent, 400, "Cannot parse input");
		ucl_object_unref (obj);
		return 0;
	}

	it = ucl_object_iterate_new (obj);

	for (i = 0; i < 4; i++) {
		cur = ucl_object_iterate_safe (it, TRUE);

		switch (i) {
		case 0:
		default:
			act = METRIC_ACTION_REJECT;
			break;
		case 1:
			act = METRIC_ACTION_REWRITE_SUBJECT;
			break;
		case 2:
			act = METRIC_ACTION_ADD_HEADER;
			break;
		case 3:
			act = METRIC_ACTION_GREYLIST;
			break;
		}

		if (ucl_object_type (cur) == UCL_NULL) {
			/* Assume NaN */
			score = NAN;
		}
		else {
			score = ucl_object_todouble (cur);
		}

		if ((isnan (session->cfg->actions[act].threshold) != isnan (score)) ||
				(session->cfg->actions[act].threshold != score)) {
			add_dynamic_action (ctx->cfg, DEFAULT_METRIC, act, score);
			added ++;
		}
		else {
			if (remove_dynamic_action (ctx->cfg, DEFAULT_METRIC, act)) {
				added ++;
			}
		}
	}

	ucl_object_iterate_free (it);

	if (dump_dynamic_config (ctx->cfg)) {
		msg_info_session ("<%s> modified %d actions",
			rspamd_inet_address_to_string (session->from_addr),
			added);

		rspamd_controller_send_string (conn_ent, "{\"success\":true}");
	}
	else {
		rspamd_controller_send_error (conn_ent, 500, "Save error");
	}

	ucl_object_unref (obj);

	return 0;
}

/*
 * Save symbols command handler:
 * request: /savesymbols
 * headers: Password
 * input: json data
 * reply: json {"success":true} or {"error":"error message"}
 */
static int
rspamd_controller_handle_savesymbols (
	struct rspamd_http_connection_entry *conn_ent,
	struct rspamd_http_message *msg)
{
	struct rspamd_controller_session *session = conn_ent->ud;
	struct ucl_parser *parser;
	ucl_object_t *obj;
	const ucl_object_t *cur, *jname, *jvalue;
	ucl_object_iter_t iter = NULL;
	struct rspamd_controller_worker_ctx *ctx;
	const gchar *error;
	gdouble val;
	struct rspamd_symbol *sym;
	int added = 0;

	ctx = session->ctx;

	if (!rspamd_controller_check_password (conn_ent, session, msg, TRUE)) {
		return 0;
	}

	if (rspamd_http_message_get_body (msg, NULL) == NULL) {
		msg_err_session ("got zero length body, cannot continue");
		rspamd_controller_send_error (conn_ent,
			400,
			"Empty body is not permitted");
		return 0;
	}

	parser = ucl_parser_new (0);
	if (!ucl_parser_add_chunk (parser, msg->body_buf.begin, msg->body_buf.len)) {
		if ((error = ucl_parser_get_error (parser)) != NULL) {
			msg_err_session ("cannot parse input: %s", error);
			rspamd_controller_send_error (conn_ent, 400, "Cannot parse input");
			ucl_parser_free (parser);
			return 0;
		}

		msg_err_session ("cannot parse input: unknown error");
		rspamd_controller_send_error (conn_ent, 400, "Cannot parse input");
		ucl_parser_free (parser);
		return 0;
	}

	obj = ucl_parser_get_object (parser);
	ucl_parser_free (parser);

	if (obj->type != UCL_ARRAY) {
		msg_err_session ("input is not an array");
		rspamd_controller_send_error (conn_ent, 400, "Cannot parse input");
		ucl_object_unref (obj);
		return 0;
	}

	iter = ucl_object_iterate_new (obj);

	while ((cur = ucl_object_iterate_safe (iter, true))) {
		if (cur->type != UCL_OBJECT) {
			msg_err_session ("json array data error");
			rspamd_controller_send_error (conn_ent, 400, "Cannot parse input");
			ucl_object_unref (obj);
			ucl_object_iterate_free (iter);

			return 0;
		}

		jname = ucl_object_lookup (cur, "name");
		jvalue = ucl_object_lookup (cur, "value");
		val = ucl_object_todouble (jvalue);
		sym = g_hash_table_lookup (session->cfg->symbols, ucl_object_tostring (jname));

		if (sym && fabs (*sym->weight_ptr - val) > 0.01) {
			if (!add_dynamic_symbol (ctx->cfg, DEFAULT_METRIC,
				ucl_object_tostring (jname), val)) {
				msg_err_session ("add symbol failed for %s",
					ucl_object_tostring (jname));
				rspamd_controller_send_error (conn_ent, 506,
					"Add symbol failed");
				ucl_object_unref (obj);
				ucl_object_iterate_free (iter);

				return 0;
			}
			added ++;
		}
		else if (sym && ctx->cfg->dynamic_conf) {
			if (remove_dynamic_symbol (ctx->cfg, DEFAULT_METRIC,
					ucl_object_tostring (jname))) {
				added ++;
			}
		}
	}

	ucl_object_iterate_free (iter);

	if (added > 0) {
		if (ctx->cfg->dynamic_conf) {
			if (dump_dynamic_config (ctx->cfg)) {
				msg_info_session ("<%s> modified %d symbols",
						rspamd_inet_address_to_string (session->from_addr),
						added);

				rspamd_controller_send_string (conn_ent, "{\"success\":true}");
			}
			else {
				rspamd_controller_send_error (conn_ent, 500, "Save error");
			}
		}
		else {
			rspamd_controller_send_string (conn_ent, "{\"success\":true}");
		}
	}
	else {
		msg_err_session ("no symbols to save");
		rspamd_controller_send_error (conn_ent, 404, "No symbols to save");
	}

	ucl_object_unref (obj);

	return 0;
}

/*
 * Save map command handler:
 * request: /savemap
 * headers: Password, Map
 * input: plaintext data
 * reply: json {"success":true} or {"error":"error message"}
 */
static int
rspamd_controller_handle_savemap (struct rspamd_http_connection_entry *conn_ent,
	struct rspamd_http_message *msg)
{
	struct rspamd_controller_session *session = conn_ent->ud;
	GList *cur;
	struct rspamd_map *map = NULL;
	struct rspamd_map_backend *bk;
	struct rspamd_controller_worker_ctx *ctx;
	const rspamd_ftok_t *idstr;
	gulong id, i;
	gboolean found = FALSE;
	gchar tempname[PATH_MAX];
	gint fd;

	ctx = session->ctx;

	if (!rspamd_controller_check_password (conn_ent, session, msg, TRUE)) {
		return 0;
	}

	if (rspamd_http_message_get_body (msg, NULL) == NULL) {
		msg_err_session ("got zero length body, cannot continue");
		rspamd_controller_send_error (conn_ent,
			400,
			"Empty body is not permitted");
		return 0;
	}

	idstr = rspamd_http_message_find_header (msg, "Map");

	if (idstr == NULL) {
		msg_info_session ("absent map id");
		rspamd_controller_send_error (conn_ent, 400, "Map id not specified");
		return 0;
	}

	if (!rspamd_strtoul (idstr->begin, idstr->len, &id)) {
		msg_info_session ("invalid map id: %T", idstr);
		rspamd_controller_send_error (conn_ent, 400, "Map id is invalid");
		return 0;
	}

	/* Now let's be sure that we have map defined in configuration */
	cur = ctx->cfg->maps;
	while (cur && !found) {
		map = cur->data;

		PTR_ARRAY_FOREACH (map->backends, i, bk) {
			if (bk->id == id && bk->protocol == MAP_PROTO_FILE) {
				found = TRUE;
				break;
			}
		}
		cur = g_list_next (cur);
	}

	if (!found) {
		msg_info_session ("map not found: %L", id);
		rspamd_controller_send_error (conn_ent, 404, "Map id not found");
		return 0;
	}

	rspamd_snprintf (tempname, sizeof (tempname), "%s.newXXXXXX", bk->uri);
	fd = g_mkstemp_full (tempname, O_WRONLY, 00644);

	if (fd == -1) {
		msg_info_session ("map %s open error: %s", tempname, strerror (errno));
		rspamd_controller_send_error (conn_ent, 404,
				"Cannot open map: %s",
				strerror (errno));
		return 0;
	}

	if (write (fd, msg->body_buf.begin, msg->body_buf.len) == -1) {
		msg_info_session ("map %s write error: %s", tempname, strerror (errno));
		unlink (tempname);
		close (fd);
		rspamd_controller_send_error (conn_ent, 500, "Map write error: %s",
				strerror (errno));
		return 0;
	}

	/* Rename */
	if (rename (tempname, bk->uri) == -1) {
		msg_info_session ("map %s rename error: %s", tempname, strerror (errno));
		unlink (tempname);
		close (fd);
		rspamd_controller_send_error (conn_ent, 500, "Map rename error: %s",
				strerror (errno));
		return 0;
	}

	msg_info_session ("<%s>, map %s saved",
			rspamd_inet_address_to_string (session->from_addr),
			bk->uri);
	close (fd);

	rspamd_controller_send_string (conn_ent, "{\"success\":true}");

	return 0;
}

struct rspamd_stat_cbdata {
	struct rspamd_http_connection_entry *conn_ent;
	ucl_object_t *top;
	ucl_object_t *stat;
	struct rspamd_task *task;
	guint64 learned;
};

static gboolean
rspamd_controller_stat_fin_task (void *ud)
{
	struct rspamd_stat_cbdata *cbdata = ud;
	struct rspamd_http_connection_entry *conn_ent;
	ucl_object_t *top, *ar;
	GList *fuzzy_elts, *cur;
	struct rspamd_fuzzy_stat_entry *entry;

	conn_ent = cbdata->conn_ent;
	top = cbdata->top;

	ucl_object_insert_key (top,
			ucl_object_fromint (cbdata->learned), "total_learns", 0, false);

	if (cbdata->stat) {
		ucl_object_insert_key (top, cbdata->stat, "statfiles", 0, false);
	}

	fuzzy_elts = rspamd_mempool_get_variable (cbdata->task->task_pool, "fuzzy_stat");

	if (fuzzy_elts) {
		ar = ucl_object_typed_new (UCL_OBJECT);

		for (cur = fuzzy_elts; cur != NULL; cur = g_list_next (cur)) {
			entry = cur->data;

			if (entry->name) {
				ucl_object_insert_key (ar, ucl_object_fromint (entry->fuzzy_cnt),
						entry->name, 0, true);
			}
		}

		ucl_object_insert_key (top, ar, "fuzzy_hashes", 0, false);
	}

	rspamd_controller_send_ucl (conn_ent, top);


	return TRUE;
}

static void
rspamd_controller_stat_cleanup_task (void *ud)
{
	struct rspamd_stat_cbdata *cbdata = ud;

	rspamd_task_free (cbdata->task);
	ucl_object_unref (cbdata->top);
}

/*
 * Stat command handler:
 * request: /stat (/resetstat)
 * headers: Password
 * reply: json data
 */
static int
rspamd_controller_handle_stat_common (
	struct rspamd_http_connection_entry *conn_ent,
	struct rspamd_http_message *msg,
	gboolean do_reset)
{
	struct rspamd_controller_session *session = conn_ent->ud;
	ucl_object_t *top, *sub;
	gint i;
	int64_t uptime;
	guint64 spam = 0, ham = 0;
	rspamd_mempool_stat_t mem_st;
	struct rspamd_stat *stat, stat_copy;
	struct rspamd_controller_worker_ctx *ctx;
	struct rspamd_task *task;
	struct rspamd_stat_cbdata *cbdata;

	memset (&mem_st, 0, sizeof (mem_st));
	rspamd_mempool_stat (&mem_st);
	memcpy (&stat_copy, session->ctx->worker->srv->stat, sizeof (stat_copy));
	stat = &stat_copy;
	ctx = session->ctx;

	task = rspamd_task_new (session->ctx->worker, session->cfg, session->pool,
			ctx->lang_det, ctx->event_loop, FALSE);
	task->resolver = ctx->resolver;
	cbdata = rspamd_mempool_alloc0 (session->pool, sizeof (*cbdata));
	cbdata->conn_ent = conn_ent;
	cbdata->task = task;
	top = ucl_object_typed_new (UCL_OBJECT);
	cbdata->top = top;

	task->s = rspamd_session_create (session->pool,
			rspamd_controller_stat_fin_task,
			NULL,
			rspamd_controller_stat_cleanup_task,
			cbdata);
	task->fin_arg = cbdata;
	task->http_conn = rspamd_http_connection_ref (conn_ent->conn);;
	task->sock = conn_ent->conn->fd;

	ucl_object_insert_key (top, ucl_object_fromstring (
			RVERSION), "version",  0, false);
	ucl_object_insert_key (top, ucl_object_fromstring (
			session->ctx->cfg->checksum), "config_id", 0, false);
	uptime = ev_time () - session->ctx->start_time;
	ucl_object_insert_key (top, ucl_object_fromint (
			uptime), "uptime", 0, false);
	ucl_object_insert_key (top, ucl_object_frombool (!session->is_enable),
			"read_only", 0, false);
	ucl_object_insert_key (top, ucl_object_fromint (
			stat->messages_scanned), "scanned", 0, false);
	ucl_object_insert_key (top, ucl_object_fromint (
			stat->messages_learned), "learned", 0, false);

	if (stat->messages_scanned > 0) {
		sub = ucl_object_typed_new (UCL_OBJECT);
		for (i = METRIC_ACTION_REJECT; i <= METRIC_ACTION_NOACTION; i++) {
			ucl_object_insert_key (sub,
				ucl_object_fromint (stat->actions_stat[i]),
				rspamd_action_to_str (i), 0, false);
			if (i < METRIC_ACTION_GREYLIST) {
				spam += stat->actions_stat[i];
			}
			else {
				ham += stat->actions_stat[i];
			}
			if (do_reset) {
#ifndef HAVE_ATOMIC_BUILTINS
				session->ctx->worker->srv->stat->actions_stat[i] = 0;
#else
				__atomic_store_n(&session->ctx->worker->srv->stat->actions_stat[i],
						0, __ATOMIC_RELEASE);
#endif
			}
		}
		ucl_object_insert_key (top, sub, "actions", 0, false);
	}

	ucl_object_insert_key (top, ucl_object_fromint (
			spam), "spam_count", 0, false);
	ucl_object_insert_key (top, ucl_object_fromint (
			ham),  "ham_count",	 0, false);
	ucl_object_insert_key (top,
		ucl_object_fromint (stat->connections_count), "connections", 0, false);
	ucl_object_insert_key (top,
		ucl_object_fromint (stat->control_connections_count),
		"control_connections", 0, false);

	ucl_object_insert_key (top,
		ucl_object_fromint (mem_st.pools_allocated), "pools_allocated", 0,
		false);
	ucl_object_insert_key (top,
		ucl_object_fromint (mem_st.pools_freed), "pools_freed", 0, false);
	ucl_object_insert_key (top,
		ucl_object_fromint (mem_st.bytes_allocated), "bytes_allocated", 0,
		false);
	ucl_object_insert_key (top,
		ucl_object_fromint (
			mem_st.chunks_allocated), "chunks_allocated", 0, false);
	ucl_object_insert_key (top,
		ucl_object_fromint (mem_st.shared_chunks_allocated),
		"shared_chunks_allocated", 0, false);
	ucl_object_insert_key (top,
		ucl_object_fromint (mem_st.chunks_freed), "chunks_freed", 0, false);
	ucl_object_insert_key (top,
		ucl_object_fromint (
			mem_st.oversized_chunks), "chunks_oversized", 0, false);
	ucl_object_insert_key (top,
			ucl_object_fromint (mem_st.fragmented_size), "fragmented", 0, false);

	if (do_reset) {
		session->ctx->srv->stat->messages_scanned = 0;
		session->ctx->srv->stat->messages_learned = 0;
		session->ctx->srv->stat->connections_count = 0;
		session->ctx->srv->stat->control_connections_count = 0;
		rspamd_mempool_stat_reset ();
	}

	fuzzy_stat_command (task);

	/* Now write statistics for each statfile */
	rspamd_stat_statistics (task, session->ctx->cfg, &cbdata->learned,
			&cbdata->stat);
	session->task = task;
	rspamd_session_pending (task->s);

	return 0;
}

static int
rspamd_controller_handle_stat (struct rspamd_http_connection_entry *conn_ent,
	struct rspamd_http_message *msg)
{
	struct rspamd_controller_session *session = conn_ent->ud;

	if (!rspamd_controller_check_password (conn_ent, session, msg, FALSE)) {
		return 0;
	}

	return rspamd_controller_handle_stat_common (conn_ent, msg, FALSE);
}

static int
rspamd_controller_handle_statreset (
	struct rspamd_http_connection_entry *conn_ent,
	struct rspamd_http_message *msg)
{
	struct rspamd_controller_session *session = conn_ent->ud;

	if (!rspamd_controller_check_password (conn_ent, session, msg, TRUE)) {
		return 0;
	}

	msg_info_session ("<%s> reset stat",
			rspamd_inet_address_to_string (session->from_addr));
	return rspamd_controller_handle_stat_common (conn_ent, msg, TRUE);
}

/*
 * Metrics command handler:
 * request: /metrics
 * headers: Password
 * reply: OpenMetrics
 */

static gboolean
rspamd_controller_metrics_fin_task (void *ud) {
	struct rspamd_stat_cbdata *cbdata = ud;
	struct rspamd_http_connection_entry *conn_ent;
	ucl_object_t *top;
	GList *fuzzy_elts, *cur;
	struct rspamd_fuzzy_stat_entry *entry;
	rspamd_fstring_t *output;
	gint i;

	conn_ent = cbdata->conn_ent;
	top = cbdata->top;

	ucl_object_insert_key (top,
			ucl_object_fromint (cbdata->learned), "total_learns", 0, false);

	output = rspamd_fstring_sized_new (1024);
	rspamd_printf_fstring (&output, "build_info{version=\"%s\"} 1\n",
		ucl_object_tostring (ucl_object_lookup (top, "version")));
	rspamd_printf_fstring (&output, "config{id=\"%s\"} 1\n",
		ucl_object_tostring (ucl_object_lookup (top, "config_id")));
	rspamd_printf_fstring (&output, "process_start_time_seconds %L\n",
		ucl_object_toint (ucl_object_lookup (top, "start_time")));
	rspamd_printf_fstring (&output, "read_only %L\n",
		ucl_object_toint (ucl_object_lookup (top, "read_only")));
	rspamd_printf_fstring (&output, "scanned %L\n",
		ucl_object_toint (ucl_object_lookup (top, "scanned")));
	rspamd_printf_fstring (&output, "learned %L\n",
		ucl_object_toint (ucl_object_lookup (top, "learned")));
	rspamd_printf_fstring (&output, "spam_count %L\n",
		ucl_object_toint (ucl_object_lookup (top, "spam_count")));
	rspamd_printf_fstring (&output, "ham_count %L\n",
		ucl_object_toint (ucl_object_lookup (top, "ham_count")));
	rspamd_printf_fstring (&output, "connections %L\n",
		ucl_object_toint (ucl_object_lookup (top, "connections")));
	rspamd_printf_fstring (&output, "control_connections %L\n",
		ucl_object_toint (ucl_object_lookup (top, "control_connections")));
	rspamd_printf_fstring (&output, "pools_allocated %L\n",
		ucl_object_toint (ucl_object_lookup (top, "pools_allocated")));
	rspamd_printf_fstring (&output, "pools_freed %L\n",
		ucl_object_toint (ucl_object_lookup (top, "pools_freed")));
	rspamd_printf_fstring (&output, "bytes_allocated %L\n",
		ucl_object_toint (ucl_object_lookup (top, "bytes_allocated")));
	rspamd_printf_fstring (&output, "chunks_allocated %L\n",
		ucl_object_toint (ucl_object_lookup (top, "chunks_allocated")));
	rspamd_printf_fstring (&output, "shared_chunks_allocated %L\n",
		ucl_object_toint (ucl_object_lookup (top, "shared_chunks_allocated")));
	rspamd_printf_fstring (&output, "chunks_freed %L\n",
		ucl_object_toint (ucl_object_lookup (top, "chunks_freed")));
	rspamd_printf_fstring (&output, "chunks_oversized %L\n",
		ucl_object_toint (ucl_object_lookup (top, "chunks_oversized")));
	rspamd_printf_fstring (&output, "fragmented %L\n",
		ucl_object_toint (ucl_object_lookup (top, "fragmented")));
	rspamd_printf_fstring (&output, "total_learns %L\n",
		ucl_object_toint (ucl_object_lookup (top, "total_learns")));

	const ucl_object_t *acts_obj = ucl_object_lookup (top, "actions");

	if (acts_obj) {
		for (i = METRIC_ACTION_REJECT; i <= METRIC_ACTION_NOACTION; i++) {
			const char *str_act = rspamd_action_to_str (i);
			const ucl_object_t *act = ucl_object_lookup (acts_obj, str_act);

			if (act) {
				rspamd_printf_fstring(&output, "actions{type=\"%s\"} %L\n",
						str_act,
						ucl_object_toint(act));
			}
			else {
				rspamd_printf_fstring (&output, "actions{type=\"%s\"} 0\n",
						str_act);
			}
		}
	}

	if (cbdata->stat) {
		const ucl_object_t *cur_elt;
		ucl_object_iter_t it = NULL;
		while ((cur_elt = ucl_object_iterate (cbdata->stat, &it, true))) {
			if (ucl_object_lookup (cur_elt, "symbol") &&
				ucl_object_lookup (cur_elt, "type")) {

				const char *sym = ucl_object_tostring (ucl_object_lookup (cur_elt, "symbol"));
				const char *type = ucl_object_tostring (ucl_object_lookup (cur_elt, "type"));

				rspamd_printf_fstring (&output, "statfiles_revision{symbol=\"%s\", type=\"%s\"} %L\n",
						sym,
						type,
						ucl_object_toint (ucl_object_lookup (cur_elt, "revision")));
				rspamd_printf_fstring (&output, "statfiles_used{symbol=\"%s\", type=\"%s\"} %L\n",
						sym,
						type,
						ucl_object_toint (ucl_object_lookup (cur_elt, "used")));
				rspamd_printf_fstring (&output, "statfiles_total{symbol=\"%s\", type=\"%s\"} %L\n",
						sym,
						type,
						ucl_object_toint (ucl_object_lookup (cur_elt, "total")));
				rspamd_printf_fstring (&output, "statfiles_size{symbol=\"%s\", type=\"%s\"} %L\n",
						sym,
						type,
						ucl_object_toint (ucl_object_lookup (cur_elt, "size")));
				rspamd_printf_fstring (&output, "statfiles_languages{symbol=\"%s\", type=\"%s\"} %L\n",
						sym,
						type,
						ucl_object_toint (ucl_object_lookup (cur_elt, "languages")));
				rspamd_printf_fstring (&output, "statfiles_users{symbol=\"%s\", type=\"%s\"} %L\n",
						sym,
						type,
						ucl_object_toint (ucl_object_lookup (cur_elt, "users")));
			}
		}
	}

	fuzzy_elts = rspamd_mempool_get_variable (cbdata->task->task_pool, "fuzzy_stat");

	if (fuzzy_elts) {
		for (cur = fuzzy_elts; cur != NULL; cur = g_list_next (cur)) {
			entry = cur->data;

			if (entry->name) {
				rspamd_printf_fstring (&output, "fuzzy_stat{storage=\"%s\"} %ud\n",
						entry->name, entry->fuzzy_cnt);
			}
		}
	}

	rspamd_printf_fstring (&output, "# EOF\n");

	rspamd_controller_send_openmetrics (conn_ent, output);

	return TRUE;
}

static int
rspamd_controller_handle_metrics_common (
	struct rspamd_http_connection_entry *conn_ent,
	struct rspamd_http_message *msg,
	gboolean do_reset)
{
	struct rspamd_controller_session *session = conn_ent->ud;
	ucl_object_t *top, *sub;
	gint i;
	int64_t uptime;
	guint64 spam = 0, ham = 0;
	rspamd_mempool_stat_t mem_st;
	struct rspamd_stat *stat, stat_copy;
	struct rspamd_controller_worker_ctx *ctx;
	struct rspamd_task *task;
	struct rspamd_stat_cbdata *cbdata;

	memset (&mem_st, 0, sizeof (mem_st));
	rspamd_mempool_stat (&mem_st);
	memcpy (&stat_copy, session->ctx->worker->srv->stat, sizeof (stat_copy));
	stat = &stat_copy;
	ctx = session->ctx;

	task = rspamd_task_new (session->ctx->worker, session->cfg, session->pool,
			ctx->lang_det, ctx->event_loop, FALSE);
	task->resolver = ctx->resolver;
	cbdata = rspamd_mempool_alloc0 (session->pool, sizeof (*cbdata));
	cbdata->conn_ent = conn_ent;
	cbdata->task = task;
	top = ucl_object_typed_new (UCL_OBJECT);
	cbdata->top = top;

	task->s = rspamd_session_create (session->pool,
			rspamd_controller_metrics_fin_task,
			NULL,
			rspamd_controller_stat_cleanup_task,
			cbdata);
	task->fin_arg = cbdata;
	task->http_conn = rspamd_http_connection_ref (conn_ent->conn);;
	task->sock = conn_ent->conn->fd;

	ucl_object_insert_key (top, ucl_object_fromstring (
			RVERSION), "version",  0, false);
	ucl_object_insert_key (top, ucl_object_fromstring (
			session->ctx->cfg->checksum), "config_id", 0, false);
	uptime = ev_time () - session->ctx->start_time;
	ucl_object_insert_key (top, ucl_object_fromint (
			uptime), "uptime", 0, false);
	ucl_object_insert_key (top, ucl_object_fromint (
			session->ctx->start_time), "start_time", 0, false);
	ucl_object_insert_key (top, ucl_object_frombool (!session->is_enable),
			"read_only", 0, false);
	ucl_object_insert_key (top, ucl_object_fromint (
			stat->messages_scanned), "scanned", 0, false);
	ucl_object_insert_key (top, ucl_object_fromint (
			stat->messages_learned), "learned", 0, false);

	if (stat->messages_scanned > 0) {
		sub = ucl_object_typed_new (UCL_OBJECT);
		for (i = METRIC_ACTION_REJECT; i <= METRIC_ACTION_NOACTION; i++) {
			ucl_object_insert_key (sub,
				ucl_object_fromint (stat->actions_stat[i]),
				rspamd_action_to_str (i), 0, false);
			if (i < METRIC_ACTION_GREYLIST) {
				spam += stat->actions_stat[i];
			}
			else {
				ham += stat->actions_stat[i];
			}
			if (do_reset) {
#ifndef HAVE_ATOMIC_BUILTINS
				session->ctx->worker->srv->stat->actions_stat[i] = 0;
#else
				__atomic_store_n(&session->ctx->worker->srv->stat->actions_stat[i],
						0, __ATOMIC_RELEASE);
#endif
			}
		}
		ucl_object_insert_key (top, sub, "actions", 0, false);
	}

	ucl_object_insert_key (top, ucl_object_fromint (
			spam), "spam_count", 0, false);
	ucl_object_insert_key (top, ucl_object_fromint (
			ham),  "ham_count",	 0, false);
	ucl_object_insert_key (top,
		ucl_object_fromint (stat->connections_count), "connections", 0, false);
	ucl_object_insert_key (top,
		ucl_object_fromint (stat->control_connections_count),
		"control_connections", 0, false);

	ucl_object_insert_key (top,
		ucl_object_fromint (mem_st.pools_allocated), "pools_allocated", 0,
		false);
	ucl_object_insert_key (top,
		ucl_object_fromint (mem_st.pools_freed), "pools_freed", 0, false);
	ucl_object_insert_key (top,
		ucl_object_fromint (mem_st.bytes_allocated), "bytes_allocated", 0,
		false);
	ucl_object_insert_key (top,
		ucl_object_fromint (
			mem_st.chunks_allocated), "chunks_allocated", 0, false);
	ucl_object_insert_key (top,
		ucl_object_fromint (mem_st.shared_chunks_allocated),
		"shared_chunks_allocated", 0, false);
	ucl_object_insert_key (top,
		ucl_object_fromint (mem_st.chunks_freed), "chunks_freed", 0, false);
	ucl_object_insert_key (top,
		ucl_object_fromint (
			mem_st.oversized_chunks), "chunks_oversized", 0, false);
	ucl_object_insert_key (top,
			ucl_object_fromint (mem_st.fragmented_size), "fragmented", 0, false);

	if (do_reset) {
		session->ctx->srv->stat->messages_scanned = 0;
		session->ctx->srv->stat->messages_learned = 0;
		session->ctx->srv->stat->connections_count = 0;
		session->ctx->srv->stat->control_connections_count = 0;
		rspamd_mempool_stat_reset ();
	}

	fuzzy_stat_command (task);

	/* Now write statistics for each statfile */
	rspamd_stat_statistics (task, session->ctx->cfg, &cbdata->learned,
			&cbdata->stat);
	session->task = task;

	rspamd_session_pending (task->s);


	return 0;
}


static int
rspamd_controller_handle_metrics (struct rspamd_http_connection_entry *conn_ent,
	struct rspamd_http_message *msg)
{
	struct rspamd_controller_session *session = conn_ent->ud;

	if (!rspamd_controller_check_password (conn_ent, session, msg, FALSE)) {
		return 0;
	}
	return rspamd_controller_handle_metrics_common (conn_ent, msg, FALSE);
}


/*
 * Counters command handler:
 * request: /counters
 * headers: Password
 * reply: json array of all counters
 */
static int
rspamd_controller_handle_counters (
	struct rspamd_http_connection_entry *conn_ent,
	struct rspamd_http_message *msg)
{
	struct rspamd_controller_session *session = conn_ent->ud;
	ucl_object_t *top;
	struct rspamd_symcache *cache;

	if (!rspamd_controller_check_password (conn_ent, session, msg, FALSE)) {
		return 0;
	}

	cache = session->ctx->cfg->cache;

	if (cache != NULL) {
		top = rspamd_symcache_counters (cache);
		rspamd_controller_send_ucl (conn_ent, top);
		ucl_object_unref (top);
	}
	else {
		rspamd_controller_send_error (conn_ent, 500, "Invalid cache");
	}

	return 0;
}

static int
rspamd_controller_handle_custom (struct rspamd_http_connection_entry *conn_ent,
	struct rspamd_http_message *msg)
{
	struct rspamd_controller_session *session = conn_ent->ud;
	struct rspamd_custom_controller_command *cmd;
	gchar *url_str;
	struct http_parser_url u;
	rspamd_ftok_t lookup;

	http_parser_parse_url (msg->url->str, msg->url->len, TRUE, &u);

	if (u.field_set & (1 << UF_PATH)) {
		gsize unnorm_len;
		lookup.begin = msg->url->str + u.field_data[UF_PATH].off;
		lookup.len = u.field_data[UF_PATH].len;

		rspamd_http_normalize_path_inplace ((gchar *)lookup.begin,
				lookup.len,
				&unnorm_len);
		lookup.len = unnorm_len;
	}
	else {
		lookup.begin = msg->url->str;
		lookup.len = msg->url->len;
	}

	url_str = rspamd_ftok_cstr (&lookup);
	cmd = g_hash_table_lookup (session->ctx->custom_commands, url_str);
	g_free (url_str);

	if (cmd == NULL || cmd->handler == NULL) {
		msg_err_session ("custom command %T has not been found", &lookup);
		rspamd_controller_send_error (conn_ent, 404, "No command associated");
		return 0;
	}

	if (!rspamd_controller_check_password (conn_ent, session, msg,
		cmd->privilleged)) {
		return 0;
	}
	if (cmd->require_message && (rspamd_http_message_get_body (msg, NULL) == NULL)) {
		msg_err_session ("got zero length body, cannot continue");
		rspamd_controller_send_error (conn_ent,
			400,
			"Empty body is not permitted");
		return 0;
	}

	/* Transfer query arguments to headers */
	if (u.field_set & (1u << UF_QUERY)) {
		GHashTable *query_args;
		GHashTableIter it;
		gpointer k, v;
		rspamd_ftok_t *key, *value;

		/* In case if we have a query, we need to store it somewhere */
		query_args = rspamd_http_message_parse_query (msg);

		/* Insert the rest of query params as HTTP headers */
		g_hash_table_iter_init (&it, query_args);

		while (g_hash_table_iter_next (&it, &k, &v)) {
			key = k;
			value = v;
			/* Steal strings */
			g_hash_table_iter_steal (&it);
			url_str = rspamd_ftok_cstr (key);
			rspamd_http_message_add_header_len (msg, url_str,
					value->begin, value->len);
			g_free (url_str);
		}

		g_hash_table_unref (query_args);
	}

	return cmd->handler (conn_ent, msg, cmd->ctx);
}

static int
rspamd_controller_handle_plugins (struct rspamd_http_connection_entry *conn_ent,
	struct rspamd_http_message *msg)
{
	struct rspamd_controller_session *session = conn_ent->ud;
	struct rspamd_controller_plugin_cbdata *cbd;
	GHashTableIter it;
	gpointer k, v;
	ucl_object_t *plugins;

	if (!rspamd_controller_check_password (conn_ent, session, msg,
			FALSE)) {
		return 0;
	}

	plugins = ucl_object_typed_new (UCL_OBJECT);
	g_hash_table_iter_init (&it, session->ctx->plugins);

	while (g_hash_table_iter_next (&it, &k, &v)) {
		ucl_object_t *elt, *npath;

		cbd = v;
		elt = (ucl_object_t *)ucl_object_lookup (plugins, cbd->plugin);

		if (elt == NULL) {
			elt = ucl_object_typed_new (UCL_OBJECT);
			ucl_object_insert_key (elt, ucl_object_fromint (cbd->version),
					"version", 0, false);
			npath = ucl_object_typed_new (UCL_ARRAY);
			ucl_object_insert_key (elt, npath, "paths", 0, false);
			ucl_object_insert_key (plugins, elt, cbd->plugin, 0, false);
		}
		else {
			npath = (ucl_object_t *)ucl_object_lookup (elt, "paths");
		}

		g_assert (npath != NULL);
		rspamd_ftok_t *key_tok = (rspamd_ftok_t *)k;
		ucl_array_append (npath, ucl_object_fromlstring (key_tok->begin, key_tok->len));
	}

	rspamd_controller_send_ucl (conn_ent, plugins);
	ucl_object_unref (plugins);

	return 0;
}

static int
rspamd_controller_handle_ping (struct rspamd_http_connection_entry *conn_ent,
		struct rspamd_http_message *msg)
{
	struct rspamd_http_message *rep_msg;
	rspamd_fstring_t *reply;

	rep_msg = rspamd_http_new_message (HTTP_RESPONSE);
	rep_msg->date = time (NULL);
	rep_msg->code = 200;
	rep_msg->status = rspamd_fstring_new_init ("OK", 2);
	reply = rspamd_fstring_new_init ("pong" CRLF, strlen ("pong" CRLF));
	rspamd_http_message_set_body_from_fstring_steal (rep_msg, reply);
	rspamd_http_connection_reset (conn_ent->conn);
	rspamd_http_router_insert_headers (conn_ent->rt, rep_msg);
	rspamd_http_connection_write_message (conn_ent->conn,
			rep_msg,
			NULL,
			"text/plain",
			conn_ent,
			conn_ent->rt->timeout);
	conn_ent->is_reply = TRUE;

	return 0;
}

/*
 * Called on unknown methods and is used to deal with CORS as per
 * https://developer.mozilla.org/en-US/docs/Web/HTTP/Access_control_CORS
 */
static int
rspamd_controller_handle_unknown (struct rspamd_http_connection_entry *conn_ent,
	struct rspamd_http_message *msg)
{
	struct rspamd_http_message *rep;

	if (msg->method == HTTP_OPTIONS) {
		/* Assume CORS request */

		rep = rspamd_http_new_message (HTTP_RESPONSE);
		rep->date = time (NULL);
		rep->code = 200;
		rep->status = rspamd_fstring_new_init ("OK", 2);
		rspamd_http_message_add_header (rep, "Access-Control-Allow-Methods",
				"POST, GET, OPTIONS");
		rspamd_http_message_add_header (rep, "Access-Control-Allow-Headers",
						"Content-Type,Password,Map,Weight,Flag");
		rspamd_http_connection_reset (conn_ent->conn);
		rspamd_http_router_insert_headers (conn_ent->rt, rep);
		rspamd_http_connection_write_message (conn_ent->conn,
				rep,
				NULL,
				"text/plain",
				conn_ent,
				conn_ent->rt->timeout);
		conn_ent->is_reply = TRUE;
	}
	else {
		rep = rspamd_http_new_message (HTTP_RESPONSE);
		rep->date = time (NULL);
		rep->code = 500;
		rep->status = rspamd_fstring_new_init ("Invalid method",
				strlen ("Invalid method"));
		rspamd_http_connection_reset (conn_ent->conn);
		rspamd_http_router_insert_headers (conn_ent->rt, rep);
		rspamd_http_connection_write_message (conn_ent->conn,
				rep,
				NULL,
				"text/plain",
				conn_ent,
				conn_ent->rt->timeout);
		conn_ent->is_reply = TRUE;
	}

	return 0;
}

static int
rspamd_controller_handle_lua_plugin (struct rspamd_http_connection_entry *conn_ent,
	struct rspamd_http_message *msg)
{
	struct rspamd_controller_session *session = conn_ent->ud;
	struct rspamd_controller_plugin_cbdata *cbd;
	struct rspamd_task *task, **ptask;
	struct rspamd_http_connection_entry **pconn;
	struct rspamd_controller_worker_ctx *ctx;
	lua_State *L;
	struct http_parser_url u;
	rspamd_ftok_t lookup;


	http_parser_parse_url (msg->url->str, msg->url->len, TRUE, &u);

	if (u.field_set & (1 << UF_PATH)) {
		gsize unnorm_len;
		lookup.begin = msg->url->str + u.field_data[UF_PATH].off;
		lookup.len = u.field_data[UF_PATH].len;

		rspamd_http_normalize_path_inplace ((gchar *)lookup.begin,
				lookup.len,
				&unnorm_len);
		lookup.len = unnorm_len;
	}
	else {
		lookup.begin = msg->url->str;
		lookup.len = msg->url->len;
	}

	cbd = g_hash_table_lookup (session->ctx->plugins, &lookup);

	if (cbd == NULL || cbd->handler == NULL) {
		msg_err_session ("plugin handler %T has not been found", &lookup);
		rspamd_controller_send_error (conn_ent, 404, "No command associated");
		return 0;
	}

	L = cbd->L;
	ctx = cbd->ctx;

	if (!rspamd_controller_check_password (conn_ent, session, msg,
		cbd->is_enable)) {
		return 0;
	}
	if (cbd->need_task && (rspamd_http_message_get_body (msg, NULL) == NULL)) {
		msg_err_session ("got zero length body, cannot continue");
		rspamd_controller_send_error (conn_ent,
			400,
			"Empty body is not permitted");
		return 0;
	}

	task = rspamd_task_new (session->ctx->worker, session->cfg, session->pool,
			ctx->lang_det, ctx->event_loop, FALSE);

	task->resolver = ctx->resolver;
	task->s = rspamd_session_create (session->pool,
			rspamd_controller_lua_fin_task,
			NULL,
			(event_finalizer_t )rspamd_task_free,
			task);
	task->fin_arg = conn_ent;
	task->http_conn = rspamd_http_connection_ref (conn_ent->conn);;
	task->sock = -1;
	session->task = task;

	if (msg->body_buf.len > 0) {
		if (!rspamd_task_load_message (task, msg, msg->body_buf.begin, msg->body_buf.len)) {
			rspamd_controller_send_error (conn_ent, task->err->code, "%s",
					task->err->message);
			return 0;
		}
	}

	/* Callback */
	lua_rawgeti (L, LUA_REGISTRYINDEX, cbd->handler->idx);

	/* Task */
	ptask = lua_newuserdata (L, sizeof (*ptask));
	rspamd_lua_setclass (L, "rspamd{task}", -1);
	*ptask = task;

	/* Connection */
	pconn = lua_newuserdata (L, sizeof (*pconn));
	rspamd_lua_setclass (L, "rspamd{csession}", -1);
	*pconn = conn_ent;

	/* Query arguments */
	GHashTable *params;
	GHashTableIter it;
	gpointer k, v;

	params = rspamd_http_message_parse_query (msg);
	lua_createtable (L, g_hash_table_size (params), 0);
	g_hash_table_iter_init (&it, params);

	while (g_hash_table_iter_next (&it, &k, &v)) {
		rspamd_ftok_t *key_tok = (rspamd_ftok_t *)k,
			*value_tok = (rspamd_ftok_t *)v;

		lua_pushlstring (L, key_tok->begin, key_tok->len);
		/* TODO: consider rspamd_text here */
		lua_pushlstring (L, value_tok->begin, value_tok->len);
		lua_settable (L, -3);
	}

	g_hash_table_unref (params);

	if (lua_pcall (L, 3, 0, 0) != 0) {
		rspamd_controller_send_error (conn_ent, 503, "Cannot run callback: %s",
				lua_tostring (L, -1));
		lua_settop (L, 0);

		return 0;
	}

	rspamd_session_pending (task->s);

	return 0;
}


static void
rspamd_controller_error_handler (struct rspamd_http_connection_entry *conn_ent,
	GError *err)
{
	struct rspamd_controller_session *session = conn_ent->ud;

	msg_err_session ("http error occurred: %s", err->message);
}

static void
rspamd_controller_finish_handler (struct rspamd_http_connection_entry *conn_ent)
{
	struct rspamd_controller_session *session = conn_ent->ud;

	session->ctx->worker->srv->stat->control_connections_count++;

	if (session->task != NULL) {
		rspamd_session_destroy (session->task->s);
	}

	session->wrk->nconns --;
	rspamd_inet_address_free (session->from_addr);
	REF_RELEASE (session->cfg);

	if (session->pool) {
		msg_debug_session ("destroy session %p", session);
		rspamd_mempool_delete (session->pool);
	}

	g_free (session);
}

static void
rspamd_controller_accept_socket (EV_P_ ev_io *w, int revents)
{
	struct rspamd_worker *worker = (struct rspamd_worker *)w->data;
	struct rspamd_controller_worker_ctx *ctx;
	struct rspamd_controller_session *session;
	rspamd_inet_addr_t *addr;
	gint nfd;

	ctx = worker->ctx;

	if ((nfd =
		rspamd_accept_from_socket (w->fd, &addr,
				rspamd_worker_throttle_accept_events, worker->accept_events)) == -1) {
		msg_warn_ctx ("accept failed: %s", strerror (errno));
		return;
	}
	/* Check for EAGAIN */
	if (nfd == 0) {
		return;
	}

	session = g_malloc0 (sizeof (struct rspamd_controller_session));
	session->pool = rspamd_mempool_new (rspamd_mempool_suggest_size (),
			"csession", 0);
	session->ctx = ctx;
	session->cfg = ctx->cfg;
	session->lang_det = ctx->lang_det;
	REF_RETAIN (session->cfg);

	session->from_addr = addr;
	session->wrk = worker;
	worker->nconns ++;

	rspamd_http_router_handle_socket (ctx->http, nfd, session);
}

static void
rspamd_controller_password_sane (struct rspamd_controller_worker_ctx *ctx,
		const gchar *password, const gchar *type)
{
	const struct rspamd_controller_pbkdf *pbkdf = &pbkdf_list[0];

	if (password == NULL) {
		msg_warn_ctx ("%s is not set, so you should filter controller "
				"availability "
				"by using of firewall or `secure_ip` option", type);
		return;
	}

	g_assert (pbkdf != NULL);

	if (!rspamd_is_encrypted_password (password, NULL)) {
		/* Suggest encryption to a user */

		msg_warn_ctx ("your %s is not encrypted, we strongly "
				"recommend to replace it with the encrypted one", type);
	}
}

gpointer
init_controller_worker (struct rspamd_config *cfg)
{
	struct rspamd_controller_worker_ctx *ctx;
	GQuark type;

	type = g_quark_try_string ("controller");

	ctx = rspamd_mempool_alloc0 (cfg->cfg_pool,
			sizeof (struct rspamd_controller_worker_ctx));

	ctx->magic = rspamd_controller_ctx_magic;
	ctx->timeout = DEFAULT_WORKER_IO_TIMEOUT;
	ctx->task_timeout = NAN;

	rspamd_rcl_register_worker_option (cfg,
			type,
			"password",
			rspamd_rcl_parse_struct_string,
			ctx,
			G_STRUCT_OFFSET (struct rspamd_controller_worker_ctx, password),
			0,
			"Password for read-only commands");

	rspamd_rcl_register_worker_option (cfg,
			type,
			"enable_password",
			rspamd_rcl_parse_struct_string,
			ctx,
			G_STRUCT_OFFSET (struct rspamd_controller_worker_ctx,
					enable_password),
			0,
			"Password for read and write commands");

	rspamd_rcl_register_worker_option (cfg,
			type,
			"ssl",
			rspamd_rcl_parse_struct_boolean,
			ctx,
			G_STRUCT_OFFSET (struct rspamd_controller_worker_ctx, use_ssl),
			0,
			"Unimplemented");

	rspamd_rcl_register_worker_option (cfg,
			type,
			"ssl_cert",
			rspamd_rcl_parse_struct_string,
			ctx,
			G_STRUCT_OFFSET (struct rspamd_controller_worker_ctx, ssl_cert),
			0,
			"Unimplemented");

	rspamd_rcl_register_worker_option (cfg,
			type,
			"ssl_key",
			rspamd_rcl_parse_struct_string,
			ctx,
			G_STRUCT_OFFSET (struct rspamd_controller_worker_ctx, ssl_key),
			0,
			"Unimplemented");
	rspamd_rcl_register_worker_option (cfg,
			type,
			"timeout",
			rspamd_rcl_parse_struct_time,
			ctx,
			G_STRUCT_OFFSET (struct rspamd_controller_worker_ctx,
					timeout),
			RSPAMD_CL_FLAG_TIME_FLOAT,
			"Protocol timeout");

	rspamd_rcl_register_worker_option (cfg,
			type,
			"secure_ip",
			rspamd_rcl_parse_struct_ucl,
			ctx,
			G_STRUCT_OFFSET (struct rspamd_controller_worker_ctx, secure_ip),
			0,
			"List of IP addresses that are allowed for password-less access");

	rspamd_rcl_register_worker_option (cfg,
			type,
			"trusted_ips",
			rspamd_rcl_parse_struct_ucl,
			ctx,
			G_STRUCT_OFFSET (struct rspamd_controller_worker_ctx, secure_ip),
			0,
			"List of IP addresses that are allowed for password-less access");

	rspamd_rcl_register_worker_option (cfg,
			type,
			"static_dir",
			rspamd_rcl_parse_struct_string,
			ctx,
			G_STRUCT_OFFSET (struct rspamd_controller_worker_ctx,
					static_files_dir),
			0,
			"Directory for static files served by controller's HTTP server");

	rspamd_rcl_register_worker_option (cfg,
			type,
			"keypair",
			rspamd_rcl_parse_struct_keypair,
			ctx,
			G_STRUCT_OFFSET (struct rspamd_controller_worker_ctx,
					key),
			0,
			"Encryption keypair");

	rspamd_rcl_register_worker_option (cfg,
			type,
			"task_timeout",
			rspamd_rcl_parse_struct_time,
			ctx,
			G_STRUCT_OFFSET (struct rspamd_controller_worker_ctx,
					task_timeout),
			RSPAMD_CL_FLAG_TIME_FLOAT,
			"Maximum task processing time, default: 8.0 seconds");

	return ctx;
}

/* Lua bindings */
LUA_FUNCTION_DEF (csession, get_ev_base);
LUA_FUNCTION_DEF (csession, get_cfg);
LUA_FUNCTION_DEF (csession, send_ucl);
LUA_FUNCTION_DEF (csession, send_string);
LUA_FUNCTION_DEF (csession, send_error);

static const struct luaL_reg lua_csessionlib_m[] = {
	LUA_INTERFACE_DEF (csession, get_ev_base),
	LUA_INTERFACE_DEF (csession, get_cfg),
	LUA_INTERFACE_DEF (csession, send_ucl),
	LUA_INTERFACE_DEF (csession, send_string),
	LUA_INTERFACE_DEF (csession, send_error),
	{"__tostring", rspamd_lua_class_tostring},
	{NULL, NULL}
};

/* Basic functions of LUA API for worker object */
static void
luaopen_controller (lua_State * L)
{
	rspamd_lua_new_class (L, "rspamd{csession}", lua_csessionlib_m);
	lua_pop (L, 1);
}

struct rspamd_http_connection_entry *
lua_check_controller_entry (lua_State * L, gint pos)
{
	void *ud = rspamd_lua_check_udata (L, pos, "rspamd{csession}");
	luaL_argcheck (L, ud != NULL, pos, "'csession' expected");
	return ud ? *((struct rspamd_http_connection_entry **)ud) : NULL;
}

static int
lua_csession_get_ev_base (lua_State *L)
{
	struct rspamd_http_connection_entry *c = lua_check_controller_entry (L, 1);
	struct ev_loop **pbase;
	struct rspamd_controller_session *s;

	if (c) {
		s = c->ud;
		pbase = lua_newuserdata (L, sizeof (struct ev_loop *));
		rspamd_lua_setclass (L, "rspamd{ev_base}", -1);
		*pbase = s->ctx->event_loop;
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static int
lua_csession_get_cfg (lua_State *L)
{
	struct rspamd_http_connection_entry *c = lua_check_controller_entry (L, 1);
	struct rspamd_config **pcfg;
	struct rspamd_controller_session *s;

	if (c) {
		s = c->ud;
		pcfg = lua_newuserdata (L, sizeof (gpointer));
		rspamd_lua_setclass (L, "rspamd{config}", -1);
		*pcfg = s->ctx->cfg;
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static int
lua_csession_send_ucl (lua_State *L)
{
	struct rspamd_http_connection_entry *c = lua_check_controller_entry (L, 1);
	ucl_object_t *obj = ucl_object_lua_import_escape (L, 2);

	if (c) {
		rspamd_controller_send_ucl (c, obj);
	}
	else {
		ucl_object_unref (obj);
		return luaL_error (L, "invalid arguments");
	}

	ucl_object_unref (obj);

	return 0;
}

static int
lua_csession_send_error (lua_State *L)
{
	struct rspamd_http_connection_entry *c = lua_check_controller_entry (L, 1);
	guint err_code = lua_tonumber (L, 2);
	const gchar *err_str = lua_tostring (L, 3);

	if (c) {
		rspamd_controller_send_error (c, err_code, "%s", err_str);
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 0;
}

static int
lua_csession_send_string (lua_State *L)
{
	struct rspamd_http_connection_entry *c = lua_check_controller_entry (L, 1);
	const gchar *str = lua_tostring (L, 2);

	if (c) {
		rspamd_controller_send_string (c, str);
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 0;
}

static void
rspamd_plugin_cbdata_dtor (gpointer p)
{
	struct rspamd_controller_plugin_cbdata *cbd = p;

	g_free (cbd->plugin);
	ucl_object_unref (cbd->obj); /* This also releases lua references */
	g_free (cbd);
}

static void
rspamd_controller_register_plugin_path (lua_State *L,
		struct rspamd_controller_worker_ctx *ctx,
		const ucl_object_t *webui_data,
		const ucl_object_t *handler,
		const gchar *path,
		const gchar *plugin_name)
{
	struct rspamd_controller_plugin_cbdata *cbd;
	const ucl_object_t *elt;
	rspamd_fstring_t *full_path;

	cbd = g_malloc0 (sizeof (*cbd));
	cbd->L = L;
	cbd->ctx = ctx;
	cbd->handler = ucl_object_toclosure (handler);
	cbd->plugin = g_strdup (plugin_name);
	cbd->obj = ucl_object_ref (webui_data);

	elt = ucl_object_lookup (webui_data, "version");

	if (elt) {
		cbd->version = ucl_object_toint (elt);
	}

	elt = ucl_object_lookup (webui_data, "enable");

	if (elt && ucl_object_toboolean (elt)) {
		cbd->is_enable = TRUE;
	}

	elt = ucl_object_lookup (webui_data, "need_task");

	if (elt && !!ucl_object_toboolean (elt)) {
		cbd->need_task = TRUE;
	}

	full_path = rspamd_fstring_new_init ("/plugins/", sizeof ("/plugins/") - 1);
	/* Zero terminated */
	rspamd_printf_fstring (&full_path, "%s/%s%c",
			plugin_name, path, '\0');

	rspamd_http_router_add_path (ctx->http,
			full_path->str,
			rspamd_controller_handle_lua_plugin);
	rspamd_ftok_t *key_tok = rspamd_ftok_map (full_path);
	/* Truncate stupid \0 symbol to enable lookup */
	key_tok->len --;
	g_hash_table_insert (ctx->plugins, key_tok, cbd);
}

static void
rspamd_controller_register_plugins_paths (struct rspamd_controller_worker_ctx *ctx)
{
	lua_State *L = ctx->cfg->lua_state;
	ucl_object_t *webui_data;
	const ucl_object_t *handler_obj, *cur;
	ucl_object_iter_t it = NULL;

	lua_getglobal (L, "rspamd_plugins");

	if (lua_istable (L, -1)) {

		for (lua_pushnil (L); lua_next (L, -2); lua_pop (L, 2)) {
			lua_pushvalue (L, -2); /* Store key */

			lua_pushstring (L, "webui");
			lua_gettable (L, -3); /* value is at -3 index */

			if (lua_istable (L, -1)) {
				webui_data = ucl_object_lua_import_escape (L, -1);

				while ((cur = ucl_object_iterate (webui_data, &it, true)) != NULL) {
					handler_obj = ucl_object_lookup (cur, "handler");

					if (handler_obj && ucl_object_key (cur)) {
						rspamd_controller_register_plugin_path (L, ctx,
								cur, handler_obj, ucl_object_key (cur),
								lua_tostring (L, -2));
					}
					else {
						msg_err_ctx ("bad webui definition for plugin: %s",
								lua_tostring (L, -2));
					}
				}

				ucl_object_unref (webui_data);
			}

			lua_pop (L, 1); /* remove table value */
		}
	}

	lua_pop (L, 1); /* rspamd_plugins global */
}

/*
 * Start worker process
 */
__attribute__((noreturn))
void
start_controller_worker (struct rspamd_worker *worker)
{
	struct rspamd_controller_worker_ctx *ctx = worker->ctx;
	struct module_ctx *mctx;
	GHashTableIter iter;
	gpointer key, value;
	guint i;
	gpointer m;

	g_assert (rspamd_worker_check_context (worker->ctx, rspamd_controller_ctx_magic));
	ctx->event_loop = rspamd_prepare_worker (worker,
			"controller",
			rspamd_controller_accept_socket);

	ctx->start_time = ev_time ();
	ctx->worker = worker;
	ctx->cfg = worker->srv->cfg;
	ctx->srv = worker->srv;
	ctx->custom_commands = g_hash_table_new (rspamd_strcase_hash,
			rspamd_strcase_equal);
	ctx->plugins = g_hash_table_new_full (rspamd_ftok_icase_hash,
			rspamd_ftok_icase_equal, rspamd_fstring_mapped_ftok_free,
			rspamd_plugin_cbdata_dtor);

	if (isnan (ctx->task_timeout)) {
		if (isnan (ctx->cfg->task_timeout)) {
			ctx->task_timeout = 0;
		}
		else {
			ctx->task_timeout = ctx->cfg->task_timeout;
		}
	}

	if (ctx->secure_ip != NULL) {
		rspamd_config_radix_from_ucl (ctx->cfg, ctx->secure_ip,
				"Allow unauthenticated requests from these addresses",
				&ctx->secure_map,
				NULL,
				worker, "controller secure ip");
	}

	ctx->lang_det = ctx->cfg->lang_det;

	rspamd_controller_password_sane (ctx, ctx->password, "normal password");
	rspamd_controller_password_sane (ctx, ctx->enable_password, "enable "
			"password");

	/* Accept event */
	ctx->http_ctx = rspamd_http_context_create (ctx->cfg, ctx->event_loop,
			ctx->cfg->ups_ctx);
	rspamd_mempool_add_destructor (ctx->cfg->cfg_pool,
			(rspamd_mempool_destruct_t)rspamd_http_context_free,
			ctx->http_ctx);
	ctx->http = rspamd_http_router_new (rspamd_controller_error_handler,
			rspamd_controller_finish_handler, ctx->timeout,
			ctx->static_files_dir, ctx->http_ctx);

	/* Add callbacks for different methods */
	rspamd_http_router_add_path (ctx->http,
			PATH_AUTH,
			rspamd_controller_handle_auth);
	rspamd_http_router_add_path (ctx->http,
			PATH_SYMBOLS,
			rspamd_controller_handle_symbols);
	rspamd_http_router_add_path (ctx->http,
			PATH_ACTIONS,
			rspamd_controller_handle_actions);
	rspamd_http_router_add_path (ctx->http,
			PATH_MAPS,
			rspamd_controller_handle_maps);
	rspamd_http_router_add_path (ctx->http,
			PATH_GET_MAP,
			rspamd_controller_handle_get_map);
	rspamd_http_router_add_path (ctx->http,
			PATH_PIE_CHART,
			rspamd_controller_handle_pie_chart);
	rspamd_http_router_add_path (ctx->http,
			PATH_GRAPH,
			rspamd_controller_handle_graph);
	rspamd_http_router_add_path (ctx->http,
			PATH_HEALTHY,
			rspamd_controller_handle_healthy);
	rspamd_http_router_add_path (ctx->http,
			PATH_READY,
			rspamd_controller_handle_ready);
	rspamd_http_router_add_path (ctx->http,
			PATH_HISTORY,
			rspamd_controller_handle_history);
	rspamd_http_router_add_path (ctx->http,
			PATH_HISTORY_RESET,
			rspamd_controller_handle_history_reset);
	rspamd_http_router_add_path (ctx->http,
			PATH_LEARN_SPAM,
			rspamd_controller_handle_learnspam);
	rspamd_http_router_add_path (ctx->http,
			PATH_LEARN_HAM,
			rspamd_controller_handle_learnham);
	rspamd_http_router_add_path (ctx->http,
			PATH_METRICS,
			rspamd_controller_handle_metrics);
	rspamd_http_router_add_path (ctx->http,
			PATH_SAVE_ACTIONS,
			rspamd_controller_handle_saveactions);
	rspamd_http_router_add_path (ctx->http,
			PATH_SAVE_SYMBOLS,
			rspamd_controller_handle_savesymbols);
	rspamd_http_router_add_path (ctx->http,
			PATH_SAVE_MAP,
			rspamd_controller_handle_savemap);
	rspamd_http_router_add_path (ctx->http,
			PATH_SCAN,
			rspamd_controller_handle_scan);
	rspamd_http_router_add_path (ctx->http,
			PATH_CHECK,
			rspamd_controller_handle_scan);
	rspamd_http_router_add_path (ctx->http,
			PATH_CHECKV2,
			rspamd_controller_handle_scan);
	rspamd_http_router_add_path (ctx->http,
			PATH_STAT,
			rspamd_controller_handle_stat);
	rspamd_http_router_add_path (ctx->http,
			PATH_STAT_RESET,
			rspamd_controller_handle_statreset);
	rspamd_http_router_add_path (ctx->http,
			PATH_COUNTERS,
			rspamd_controller_handle_counters);
	rspamd_http_router_add_path (ctx->http,
			PATH_ERRORS,
			rspamd_controller_handle_errors);
	rspamd_http_router_add_path (ctx->http,
			PATH_NEIGHBOURS,
			rspamd_controller_handle_neighbours);
	rspamd_http_router_add_path (ctx->http,
			PATH_PLUGINS,
			rspamd_controller_handle_plugins);
	rspamd_http_router_add_path (ctx->http,
			PATH_PING,
			rspamd_controller_handle_ping);
	rspamd_controller_register_plugins_paths (ctx);

#if 0
	rspamd_regexp_t *lua_re = rspamd_regexp_new ("^/.*/.*\\.lua$", NULL, NULL);
	rspamd_http_router_add_regexp (ctx->http, lua_re,
			rspamd_controller_handle_lua);
	rspamd_regexp_unref (lua_re);
#endif
	luaopen_controller (ctx->cfg->lua_state);

	if (ctx->key) {
		rspamd_http_router_set_key (ctx->http, ctx->key);
	}

	PTR_ARRAY_FOREACH (ctx->cfg->c_modules, i, mctx) {
		if (mctx->mod->module_attach_controller_func != NULL) {
			mctx->mod->module_attach_controller_func (mctx,
					ctx->custom_commands);
		}
	}

	g_hash_table_iter_init (&iter, ctx->custom_commands);
	while (g_hash_table_iter_next (&iter, &key, &value)) {
		rspamd_http_router_add_path (ctx->http,
			key,
			rspamd_controller_handle_custom);
	}

	if (worker->srv->cfg->neighbours && worker->srv->cfg->neighbours->len > 0) {
		rspamd_http_router_add_header (ctx->http,
				"Access-Control-Allow-Origin", "*");
	}

	/* Disable all results caching, see #3330 */
	rspamd_http_router_add_header (ctx->http,
			"Cache-Control", "no-store");

	rspamd_http_router_set_unknown_handler (ctx->http,
			rspamd_controller_handle_unknown);

	ctx->resolver = rspamd_dns_resolver_init (worker->srv->logger,
			ctx->event_loop,
			worker->srv->cfg);

	rspamd_upstreams_library_config (worker->srv->cfg, worker->srv->cfg->ups_ctx,
			ctx->event_loop, ctx->resolver->r);
	rspamd_symcache_start_refresh (worker->srv->cfg->cache, ctx->event_loop,
			worker);
	rspamd_stat_init (worker->srv->cfg, ctx->event_loop);
	rspamd_worker_init_controller (worker, &ctx->rrd);
	rspamd_lua_run_postloads (ctx->cfg->lua_state, ctx->cfg, ctx->event_loop, worker);

#ifdef WITH_HYPERSCAN
	rspamd_control_worker_add_cmd_handler (worker,
			RSPAMD_CONTROL_HYPERSCAN_LOADED,
			rspamd_worker_hyperscan_ready,
			NULL);
#endif

	/* Start event loop */
	ev_loop (ctx->event_loop, 0);
	rspamd_worker_block_signals ();
	rspamd_controller_on_terminate (worker, ctx->rrd);

	rspamd_stat_close ();
	rspamd_http_router_free (ctx->http);

	if (ctx->cached_password.len > 0) {
		m = (gpointer)ctx->cached_password.begin;
		munmap (m, ctx->cached_password.len);
	}

	if (ctx->cached_enable_password.len > 0) {
		m = (gpointer) ctx->cached_enable_password.begin;
		munmap (m, ctx->cached_enable_password.len);
	}

	g_hash_table_unref (ctx->plugins);
	g_hash_table_unref (ctx->custom_commands);

	REF_RELEASE (ctx->cfg);
	rspamd_log_close (worker->srv->logger);

	exit (EXIT_SUCCESS);
}
