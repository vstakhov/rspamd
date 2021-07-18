/*-
 * Copyright 2016-2017 Vsevolod Stakhov
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

#ifndef CFG_FILE_H
#define CFG_FILE_H

#include "config.h"
#include "mem_pool.h"
#include "upstream.h"
#include "rspamd_symcache.h"
#include "cfg_rcl.h"
#include "ucl.h"
#include "regexp.h"
#include "libserver/re_cache.h"
#include "libutil/ref.h"
#include "libutil/radix.h"
#include "monitored.h"
#include "redis_pool.h"

#define DEFAULT_BIND_PORT 11333
#define DEFAULT_CONTROL_PORT 11334

/* Default metric name */
#define DEFAULT_METRIC "default"

#ifdef  __cplusplus
extern "C" {
#endif

struct expression;
struct tokenizer;
struct rspamd_stat_classifier;
struct module_s;
struct worker_s;
struct rspamd_external_libs_ctx;
struct rspamd_cryptobox_pubkey;
struct rspamd_dns_resolver;

/**
 * Types of rspamd bind lines
 */
enum rspamd_cred_type {
	CRED_NORMAL,
	CRED_CONTROL,
	CRED_LMTP,
	CRED_DELIVERY
};

/**
 * Logging type
 */
enum rspamd_log_type {
	RSPAMD_LOG_CONSOLE,
	RSPAMD_LOG_SYSLOG,
	RSPAMD_LOG_FILE
};

enum rspamd_log_cfg_flags {
	RSPAMD_LOG_FLAG_DEFAULT = 0,
	RSPAMD_LOG_FLAG_SYSTEMD = (1 << 0),
	RSPAMD_LOG_FLAG_COLOR = (1 << 1),
	RSPAMD_LOG_FLAG_RE_CACHE = (1 << 2),
	RSPAMD_LOG_FLAG_USEC = (1 << 3),
	RSPAMD_LOG_FLAG_RSPAMADM = (1 << 4),
	RSPAMD_LOG_FLAG_ENFORCED = (1 << 5),
	RSPAMD_LOG_FLAG_SEVERITY = (1 << 6),
};

struct rspamd_worker_log_pipe {
	gint fd;
	gint type;
	struct rspamd_worker_log_pipe *prev, *next;
};

/**
 * script module list item
 */
struct script_module {
	gchar *name;                                    /**< name of module   */
	gchar *path;                                    /**< path to module   */
	gchar *digest;
};

/**
 * Type of lua variable
 */
enum lua_var_type {
	LUA_VAR_NUM,
	LUA_VAR_BOOLEAN,
	LUA_VAR_STRING,
	LUA_VAR_FUNCTION,
	LUA_VAR_UNKNOWN
};

enum rspamd_symbol_group_flags {
	RSPAMD_SYMBOL_GROUP_NORMAL = 0u,
	RSPAMD_SYMBOL_GROUP_DISABLED = (1u << 0u),
	RSPAMD_SYMBOL_GROUP_ONE_SHOT = (1u << 1u),
	RSPAMD_SYMBOL_GROUP_UNGROUPED = (1u << 2u),
	RSPAMD_SYMBOL_GROUP_PUBLIC = (1u << 3u),
};

/**
 * Symbols group
 */
struct rspamd_symbol;
struct rspamd_symbols_group {
	gchar *name;
	gchar *description;
	GHashTable *symbols;
	gdouble max_score;
	guint flags;
};

enum rspamd_symbol_flags {
	RSPAMD_SYMBOL_FLAG_NORMAL = 0,
	RSPAMD_SYMBOL_FLAG_IGNORE_METRIC = (1 << 1),
	RSPAMD_SYMBOL_FLAG_ONEPARAM = (1 << 2),
	RSPAMD_SYMBOL_FLAG_UNGROUPPED = (1 << 3),
	RSPAMD_SYMBOL_FLAG_DISABLED = (1 << 4),
	RSPAMD_SYMBOL_FLAG_UNSCORED = (1 << 5),
};

/**
 * Symbol config definition
 */
struct rspamd_symbol {
	gchar *name;
	gchar *description;
	gdouble *weight_ptr;
	gdouble score;
	guint priority;
	struct rspamd_symbols_group *gr; /* Main group */
	GPtrArray *groups; /* Other groups */
	guint flags;
	struct rspamd_symcache_item *cache_item;
	gint nshots;
};

/**
 * Statfile config definition
 */
struct rspamd_statfile_config {
	gchar *symbol;                                  /**< symbol of statfile									*/
	gchar *label;                                   /**< label of this statfile								*/
	ucl_object_t *opts;                             /**< other options										*/
	gboolean is_spam;                               /**< spam flag											*/
	struct rspamd_classifier_config *clcf;            /**< parent pointer of classifier configuration			*/
	gpointer data;                                    /**< opaque data 										*/
};

struct rspamd_tokenizer_config {
	const ucl_object_t *opts;                        /**< other options										*/
	const gchar *name;                                /**< name of tokenizer									*/
};


/* Classifier has all integer values (e.g. bayes) */
#define RSPAMD_FLAG_CLASSIFIER_INTEGER (1 << 0)
/*
 * Set if backend for a classifier is intended to increment and not set values
 * (e.g. redis)
 */
#define RSPAMD_FLAG_CLASSIFIER_INCREMENTING_BACKEND (1 << 1)
/*
 * No backend required for classifier
 */
#define RSPAMD_FLAG_CLASSIFIER_NO_BACKEND (1 << 2)

/**
 * Classifier config definition
 */
struct rspamd_classifier_config {
	GList *statfiles;                               /**< statfiles list                                     */
	GHashTable *labels;                             /**< statfiles with labels								*/
	gchar *metric;                                  /**< metric of this classifier                          */
	gchar *classifier;                              /**< classifier interface                               */
	struct rspamd_tokenizer_config *tokenizer;      /**< tokenizer used for classifier						*/
	const gchar *backend;                           /**< name of statfile's backend							*/
	ucl_object_t *opts;                             /**< other options                                      */
	GList *learn_conditions;                        /**< list of learn condition callbacks					*/
	gchar *name;                                    /**< unique name of classifier							*/
	guint32 min_tokens;                             /**< minimal number of tokens to process classifier 	*/
	guint32 max_tokens;                             /**< maximum number of tokens							*/
	guint min_token_hits;                           /**< minimum number of hits for a token to be considered */
	gdouble min_prob_strength;                      /**< use only tokens with probability in [0.5 - MPS, 0.5 + MPS] */
	guint min_learns;                               /**< minimum number of learns for each statfile			*/
	guint flags;
};

struct rspamd_worker_bind_conf {
	GPtrArray *addrs;
	guint cnt;
	gchar *name;
	gchar *bind_line;
	gboolean is_systemd;
	struct rspamd_worker_bind_conf *next;
};

struct rspamd_worker_lua_script {
	gint cbref;
	struct rspamd_worker_lua_script *prev, *next;
};

/**
 * Config params for rspamd worker
 */
struct rspamd_worker_conf {
	struct worker_s *worker;                        /**< pointer to worker type								*/
	GQuark type;                                    /**< type of worker										*/
	struct rspamd_worker_bind_conf *bind_conf;      /**< bind configuration									*/
	gint16 count;                                   /**< number of workers									*/
	GList *listen_socks;                            /**< listening sockets descriptors						*/
	guint64 rlimit_nofile;                          /**< max files limit									*/
	guint64 rlimit_maxcore;                         /**< maximum core file size								*/
	GHashTable *params;                             /**< params for worker									*/
	GQueue *active_workers;                         /**< linked list of spawned workers						*/
	gpointer *ctx;                                  /**< worker's context									*/
	ucl_object_t *options;                          /**< other worker's options								*/
	struct rspamd_worker_lua_script *scripts;       /**< registered lua scripts								*/
	gboolean enabled;
	ref_entry_t ref;
};

enum rspamd_log_format_type {
	RSPAMD_LOG_STRING = 0,
	RSPAMD_LOG_MID,
	RSPAMD_LOG_QID,
	RSPAMD_LOG_USER,
	RSPAMD_LOG_ISSPAM,
	RSPAMD_LOG_ACTION,
	RSPAMD_LOG_SCORES,
	RSPAMD_LOG_SYMBOLS,
	RSPAMD_LOG_IP,
	RSPAMD_LOG_LEN,
	RSPAMD_LOG_DNS_REQ,
	RSPAMD_LOG_SMTP_FROM,
	RSPAMD_LOG_MIME_FROM,
	RSPAMD_LOG_SMTP_RCPT,
	RSPAMD_LOG_MIME_RCPT,
	RSPAMD_LOG_SMTP_RCPTS,
	RSPAMD_LOG_MIME_RCPTS,
	RSPAMD_LOG_TIME_REAL,
	RSPAMD_LOG_TIME_VIRTUAL,
	RSPAMD_LOG_LUA,
	RSPAMD_LOG_DIGEST,
	RSPAMD_LOG_FILENAME,
	RSPAMD_LOG_FORCED_ACTION,
	RSPAMD_LOG_SETTINGS_ID,
	RSPAMD_LOG_GROUPS,
	RSPAMD_LOG_PUBLIC_GROUPS,
	RSPAMD_LOG_MEMPOOL_SIZE,
	RSPAMD_LOG_MEMPOOL_WASTE,
};

enum rspamd_log_format_flags {
	RSPAMD_LOG_FMT_FLAG_DEFAULT = 0,
	RSPAMD_LOG_FMT_FLAG_OPTIONAL = (1 << 0),
	RSPAMD_LOG_FMT_FLAG_MIME_ALTERNATIVE = (1 << 1),
	RSPAMD_LOG_FMT_FLAG_CONDITION = (1 << 2),
	RSPAMD_LOG_FMT_FLAG_SYMBOLS_SCORES = (1 << 3),
	RSPAMD_LOG_FMT_FLAG_SYMBOLS_PARAMS = (1 << 4)
};

struct rspamd_log_format {
	enum rspamd_log_format_type type;
	guint flags;
	gsize len;
	gpointer data;
	struct rspamd_log_format *prev, *next;
};

/**
 * Standard actions
 */
enum rspamd_action_type {
	METRIC_ACTION_REJECT = 0,
	METRIC_ACTION_SOFT_REJECT,
	METRIC_ACTION_REWRITE_SUBJECT,
	METRIC_ACTION_ADD_HEADER,
	METRIC_ACTION_GREYLIST,
	METRIC_ACTION_NOACTION,
	METRIC_ACTION_MAX,
	METRIC_ACTION_CUSTOM = 999,
	METRIC_ACTION_DISCARD,
	METRIC_ACTION_QUARANTINE
};

enum rspamd_action_flags {
	RSPAMD_ACTION_NORMAL = 0u,
	RSPAMD_ACTION_NO_THRESHOLD = (1u << 0u),
	RSPAMD_ACTION_THRESHOLD_ONLY = (1u << 1u),
	RSPAMD_ACTION_HAM = (1u << 2u),
	RSPAMD_ACTION_MILTER = (1u << 3u),
};


struct rspamd_action;

struct rspamd_config_cfg_lua_script {
	gint cbref;
	gint priority;
	gchar *lua_src_pos;
	struct rspamd_config_cfg_lua_script *prev, *next;
};

struct rspamd_config_post_init_script {
	gint cbref;
	struct rspamd_config_post_init_script *prev, *next;
};

struct rspamd_lang_detector;

enum rspamd_config_settings_policy {
	RSPAMD_SETTINGS_POLICY_DEFAULT = 0,
	RSPAMD_SETTINGS_POLICY_IMPLICIT_ALLOW = 1,
	RSPAMD_SETTINGS_POLICY_IMPLICIT_DENY = 2,
};

struct rspamd_config_settings_elt {
	guint32 id;
	enum rspamd_config_settings_policy policy;
	const gchar *name;
	ucl_object_t *symbols_enabled;
	ucl_object_t *symbols_disabled;
	struct rspamd_config_settings_elt *prev, *next;
	ref_entry_t ref;
};

/**
 * Structure that stores all config data
 */
struct rspamd_config {
	gchar *rspamd_user;                             /**< user to run as										*/
	gchar *rspamd_group;                            /**< group to run as									*/
	rspamd_mempool_t *cfg_pool;                     /**< memory pool for config								*/
	gchar *cfg_name;                                /**< name of config file								*/
	gchar *pid_file;                                /**< name of pid file									*/
	gchar *temp_dir;                                /**< dir for temp files									*/
	gchar *control_socket_path;                     /**< path to the control socket							*/
	const ucl_object_t *local_addrs;                /**< tree of local addresses							*/
#ifdef WITH_GPERF_TOOLS
	gchar *profile_path;
#endif
	gdouble unknown_weight;                         /**< weight of unknown symbols						*/
	gdouble grow_factor;                            /**< grow factor for metric							*/
	GHashTable *symbols;                            /**< weights of symbols in metric					*/
	const gchar *subject;                           /**< subject rewrite string							*/
	GHashTable *groups;                            /**< groups of symbols								*/
	struct rspamd_action *actions;                  /**< all actions of the metric						*/

	gboolean raw_mode;                              /**< work in raw mode instead of utf one				*/
	gboolean one_shot_mode;                         /**< rules add only one symbol							*/
	gboolean check_text_attachements;               /**< check text attachements as text					*/
	gboolean check_all_filters;                     /**< check all filters									*/
	gboolean allow_raw_input;                       /**< scan messages with invalid mime					*/
	gboolean disable_hyperscan;                     /**< disable hyperscan usage							*/
	gboolean vectorized_hyperscan;                  /**< use vectorized hyperscan matching					*/
	gboolean enable_shutdown_workaround;            /**< enable workaround for legacy SA clients (exim)		*/
	gboolean ignore_received;                       /**< Ignore data from the first received header			*/
	gboolean enable_sessions_cache;                 /**< Enable session cache for debug						*/
	gboolean enable_experimental;                   /**< Enable experimental plugins						*/
	gboolean disable_pcre_jit;                      /**< Disable pcre JIT									*/
	gboolean own_lua_state;                         /**< True if we have created lua_state internally		*/
	gboolean soft_reject_on_timeout;                /**< If true emit soft reject on task timeout (if not reject) */
	gboolean public_groups_only;                    /**< Output merely public groups everywhere				*/
	gboolean enable_test_patterns;                  /**< Enable test patterns								*/
	gboolean enable_css_parser;                     /**< Enable css parsing in HTML							*/

	gsize max_cores_size;                           /**< maximum size occupied by rspamd core files			*/
	gsize max_cores_count;                          /**< maximum number of core files						*/
	gchar *cores_dir;                               /**< directory for core files							*/
	gsize max_message;                              /**< maximum size for messages							*/
	gsize max_pic_size;                             /**< maximum size for a picture to process				*/
	gsize images_cache_size;                        /**< size of LRU cache for DCT data from images			*/
	gdouble task_timeout;                           /**< maximum message processing time					*/
	gint default_max_shots;                         /**< default maximum count of symbols hits permitted (-1 for unlimited) */
	gint32 heartbeats_loss_max;                     /**< number of heartbeats lost to consider worker's termination */
	gdouble heartbeat_interval;                     /**< interval for heartbeats for workers				*/

	enum rspamd_log_type log_type;                  /**< log type											*/
	gint log_facility;                              /**< log facility in case of syslog						*/
	gint log_level;                                 /**< log level trigger									*/
	gchar *log_file;                                /**< path to logfile in case of file logging			*/
	gboolean log_buffered;                          /**< whether logging is buffered						*/
	gboolean log_silent_workers;                    /**< silence info messages from workers					*/
	guint32 log_buf_size;                           /**< length of log buffer								*/
	const ucl_object_t *debug_ip_map;               /**< turn on debugging for specified ip addresses       */
	gboolean log_urls;                              /**< whether we should log URLs                         */
	GHashTable *debug_modules;                      /**< logging modules to debug							*/
	struct rspamd_cryptobox_pubkey *log_encryption_key; /**< encryption key for logs						*/
	guint log_flags;                                /**< logging flags										*/
	guint log_error_elts;                           /**< number of elements in error logbuf					*/
	guint log_error_elt_maxlen;                     /**< maximum size of error log element					*/
	struct rspamd_worker_log_pipe *log_pipes;

	gboolean compat_messages;                       /**< use old messages in the protocol (array) 			*/

	GList *script_modules;                          /**< linked list of script modules to load				*/
	GHashTable *explicit_modules;                   /**< modules that should be always loaded				*/

	GList *filters;                                 /**< linked list of all filters							*/
	GList *workers;                                 /**< linked list of all workers params					*/
	GHashTable *wrk_parsers;                        /**< hash for worker config parsers, indexed by worker quarks */
	ucl_object_t *rcl_obj;                          /**< rcl object											*/
	ucl_object_t *config_comments;                  /**< comments saved from the config						*/
	ucl_object_t *doc_strings;                      /**< documentation strings for config options			*/
	GPtrArray *c_modules;                           /**< list of C modules			*/
	void *composites_manager;                       /**< hash of composite symbols indexed by its name		*/
	GList *classifiers;                             /**< list of all classifiers defined                    */
	GList *statfiles;                               /**< list of all statfiles in config file order         */
	GHashTable *classifiers_symbols;                /**< hashtable indexed by symbol name of classifiers    */
	GHashTable *cfg_params;                        /**< all cfg params indexed by its name in this structure */
	gchar *dynamic_conf;                            /**< path to dynamic configuration						*/
	ucl_object_t *current_dynamic_conf;             /**< currently loaded dynamic configuration				*/
	gint clock_res;                                 /**< resolution of clock used							*/

	GList *maps;                                    /**< maps active										*/
	gdouble map_timeout;                            /**< maps watch timeout									*/
	gdouble map_file_watch_multiplier;              /**< multiplier for watch timeout when maps are files	*/
	gchar *maps_cache_dir;                          /**< where to save HTTP cached data						*/

	gdouble monitored_interval;                     /**< interval between monitored checks					*/
	gboolean disable_monitored;                     /**< disable monitoring completely						*/
	gboolean fips_mode;                             /**< turn on fips mode for openssl						*/

	struct rspamd_symcache *cache;                    /**< symbols cache object								*/
	gchar *cache_filename;                          /**< filename of cache file								*/
	gdouble cache_reload_time;                      /**< how often cache reload should be performed			*/
	gchar *checksum;                               /**< real checksum of config file						*/
	gpointer lua_state;                             /**< pointer to lua state								*/
	gpointer lua_thread_pool;                       /**< pointer to lua thread (coroutine) pool				*/

	gchar *rrd_file;                               /**< rrd file to store statistics						*/
	gchar *history_file;                           /**< file to save rolling history						*/
	gchar *stats_file;                           /**< file to save stats 						*/
	gchar *tld_file;                               /**< file to load effective tld list from				*/
	gchar *hs_cache_dir;                           /**< directory to save hyperscan databases				*/
	gchar *events_backend;                         /**< string representation of the events backend used	*/

	gdouble dns_timeout;                            /**< timeout in milliseconds for waiting for dns reply	*/
	guint32 dns_retransmits;                        /**< maximum retransmits count							*/
	guint32 dns_io_per_server;                      /**< number of sockets per DNS server					*/
	const ucl_object_t *nameservers;                /**< list of nameservers or NULL to parse resolv.conf	*/
	guint32 dns_max_requests;                       /**< limit of DNS requests per task 					*/
	gboolean enable_dnssec;                         /**< enable dnssec stub resolver						*/

	guint upstream_max_errors;                        /**< upstream max errors before shutting off			*/
	gdouble upstream_error_time;                    /**< rate of upstream errors							*/
	gdouble upstream_revive_time;                    /**< revive timeout for upstreams						*/
	gdouble upstream_lazy_resolve_time;              /**< lazy resolve time for upstreams					*/
	struct upstream_ctx *ups_ctx;                    /**< upstream context									*/
	struct rspamd_dns_resolver *dns_resolver;        /**< dns resolver if loaded								*/

	guint min_word_len;                                /**< minimum length of the word to be considered		*/
	guint max_word_len;                                /**< maximum length of the word to be considered		*/
	guint words_decay;                                /**< limit for words for starting adaptive ignoring		*/
	guint history_rows;                                /**< number of history rows stored						*/
	guint max_sessions_cache;                        /**< maximum number of sessions cache elts				*/
	guint lua_gc_step;                                /**< lua gc step 										*/
	guint lua_gc_pause;                                /**< lua gc pause										*/
	guint full_gc_iters;                            /**< iterations between full gc cycle					*/
	guint max_lua_urls;                             /**< maximum number of urls to be passed to Lua			*/
	guint max_urls;                                 /**< maximum number of urls to be processed in general	*/
	gint max_recipients;                           /**< maximum number of recipients to be processed	*/
	guint max_blas_threads;                         /**< maximum threads for openblas when learning ANN		*/
	guint max_opts_len;                             /**< maximum length for all options for a symbol		*/

	GList *classify_headers;                        /**< list of headers using for statistics				*/
	struct module_s **compiled_modules;                /**< list of compiled C modules							*/
	struct worker_s **compiled_workers;                /**< list of compiled C modules							*/
	struct rspamd_log_format *log_format;            /**< parsed log format									*/
	gchar *log_format_str;                            /**< raw log format string								*/

	struct rspamd_external_libs_ctx *libs_ctx;        /**< context for external libraries						*/
	struct rspamd_monitored_ctx *monitored_ctx;        /**< context for monitored resources					*/
	struct rspamd_redis_pool *redis_pool;            /**< redis connection pool								*/

	struct rspamd_re_cache *re_cache;                /**< static regexp cache								*/

	GHashTable *trusted_keys;                        /**< list of trusted public keys						*/

	struct rspamd_config_cfg_lua_script *on_load_scripts;    /**< list of scripts executed on workers load			*/
	struct rspamd_config_cfg_lua_script *post_init_scripts;    /**< list of scripts executed on config being fully loaded			*/
	struct rspamd_config_cfg_lua_script *on_term_scripts; /**< list of callbacks called on worker's termination	*/
	struct rspamd_config_cfg_lua_script *config_unload_scripts;    /**< list of scripts executed on config unload			*/

	gchar *ssl_ca_path;                                /**< path to CA certs									*/
	gchar *ssl_ciphers;                                /**< set of preferred ciphers							*/
	gchar *zstd_input_dictionary;                    /**< path to zstd input dictionary						*/
	gchar *zstd_output_dictionary;                    /**< path to zstd output dictionary						*/
	ucl_object_t *neighbours;                        /**< other servers in the cluster						*/

	struct rspamd_config_settings_elt *setting_ids;    /**< preprocessed settings ids							*/
	struct rspamd_lang_detector *lang_det;            /**< language detector									*/
	struct rspamd_worker *cur_worker;               /**< set dynamically by each worker							*/

	ref_entry_t ref;                                /**< reference counter									*/
};


/**
 * Parse bind credits
 * @param cf config file to use
 * @param str line that presents bind line
 * @param type type of credits
 * @return 1 if line was successfully parsed and 0 in case of error
 */
gboolean rspamd_parse_bind_line (struct rspamd_config *cfg,
								 struct rspamd_worker_conf *cf, const gchar *str);


enum rspamd_config_init_flags {
	RSPAMD_CONFIG_INIT_DEFAULT = 0u,
	RSPAMD_CONFIG_INIT_SKIP_LUA = (1u << 0u),
	RSPAMD_CONFIG_INIT_WIPE_LUA_MEM = (1u << 1u),
};

/**
 * Init default values
 * @param cfg config file
 */
struct rspamd_config *rspamd_config_new (enum rspamd_config_init_flags flags);

/**
 * Free memory used by config structure
 * @param cfg config file
 */
void rspamd_config_free (struct rspamd_config *cfg);

/**
 * Gets module option with specified name
 * @param cfg config file
 * @param module_name name of module
 * @param opt_name name of option to get
 * @return module value or NULL if option does not defined
 */
const ucl_object_t *rspamd_config_get_module_opt (struct rspamd_config *cfg,
												  const gchar *module_name,
												  const gchar *opt_name) G_GNUC_WARN_UNUSED_RESULT;


/**
 * Parse flag
 * @param str string representation of flag (eg. 'on')
 * @return numeric value of flag (0 or 1)
 */
gchar rspamd_config_parse_flag (const gchar *str, guint len);

enum rspamd_post_load_options {
	RSPAMD_CONFIG_INIT_URL = 1 << 0,
	RSPAMD_CONFIG_INIT_LIBS = 1 << 1,
	RSPAMD_CONFIG_INIT_SYMCACHE = 1 << 2,
	RSPAMD_CONFIG_INIT_VALIDATE = 1 << 3,
	RSPAMD_CONFIG_INIT_NO_TLD = 1 << 4,
	RSPAMD_CONFIG_INIT_PRELOAD_MAPS = 1 << 5,
	RSPAMD_CONFIG_INIT_POST_LOAD_LUA = 1 << 6,
};

#define RSPAMD_CONFIG_LOAD_ALL (RSPAMD_CONFIG_INIT_URL| \
        RSPAMD_CONFIG_INIT_LIBS| \
        RSPAMD_CONFIG_INIT_SYMCACHE| \
        RSPAMD_CONFIG_INIT_VALIDATE| \
        RSPAMD_CONFIG_INIT_PRELOAD_MAPS| \
        RSPAMD_CONFIG_INIT_POST_LOAD_LUA)

/**
 * Do post load actions for config
 * @param cfg config file
 */
gboolean rspamd_config_post_load (struct rspamd_config *cfg,
								  enum rspamd_post_load_options opts);

/**
 * Calculate checksum for config file
 * @param cfg config file
 */
gboolean rspamd_config_calculate_checksum (struct rspamd_config *cfg);


/**
 * Replace all \" with a single " in given string
 * @param line input string
 */
void rspamd_config_unescape_quotes (gchar *line);

/*
 * Convert comma separated string to a list of strings
 */
GList *rspamd_config_parse_comma_list (rspamd_mempool_t *pool,
									   const gchar *line);

/*
 * Return a new classifier_config structure, setting default and non-conflicting attributes
 */
struct rspamd_classifier_config *rspamd_config_new_classifier (
		struct rspamd_config *cfg,
		struct rspamd_classifier_config *c);

/*
 * Return a new worker_conf structure, setting default and non-conflicting attributes
 */
struct rspamd_worker_conf *rspamd_config_new_worker (struct rspamd_config *cfg,
													 struct rspamd_worker_conf *c);

/*
 * Return a new metric structure, setting default and non-conflicting attributes
 */
void rspamd_config_init_metric (struct rspamd_config *cfg);

/*
 * Return new symbols group definition
 */
struct rspamd_symbols_group *rspamd_config_new_group (
		struct rspamd_config *cfg,
		const gchar *name);

/*
 * Return a new statfile structure, setting default and non-conflicting attributes
 */
struct rspamd_statfile_config *rspamd_config_new_statfile (
		struct rspamd_config *cfg,
		struct rspamd_statfile_config *c);

/*
 * Register symbols of classifiers inside metrics
 */
void rspamd_config_insert_classify_symbols (struct rspamd_config *cfg);

/*
 * Check statfiles inside a classifier
 */
gboolean rspamd_config_check_statfiles (struct rspamd_classifier_config *cf);

/*
 * Find classifier config by name
 */
struct rspamd_classifier_config *rspamd_config_find_classifier (
		struct rspamd_config *cfg,
		const gchar *name);

void rspamd_ucl_add_conf_macros (struct ucl_parser *parser,
								 struct rspamd_config *cfg);

void rspamd_ucl_add_conf_variables (struct ucl_parser *parser, GHashTable *vars);

/**
 * Initialize rspamd filtering system (lua and C filters)
 * @param cfg
 * @param reconfig
 * @return
 */
gboolean rspamd_init_filters (struct rspamd_config *cfg, bool reconfig, bool strict);

/**
 * Add new symbol to the metric
 * @param cfg
 * @param metric metric's name (or NULL for the default metric)
 * @param symbol symbol's name
 * @param score symbol's score
 * @param description optional description
 * @param group optional group name
 * @param one_shot TRUE if symbol can add its score once
 * @param rewrite_existing TRUE if we need to rewrite the existing symbol
 * @param priority use the following priority for a symbol
 * @param nshots means maximum number of hits for a symbol in metric (-1 for unlimited)
 * @return TRUE if symbol has been inserted or FALSE if symbol already exists with higher priority
 */
gboolean rspamd_config_add_symbol (struct rspamd_config *cfg,
								   const gchar *symbol,
								   gdouble score,
								   const gchar *description,
								   const gchar *group,
								   guint flags,
								   guint priority,
								   gint nshots);

/**
 * Adds new group for a symbol
 * @param cfg
 * @param symbol
 * @param group
 * @return
 */
gboolean rspamd_config_add_symbol_group (struct rspamd_config *cfg,
										 const gchar *symbol,
										 const gchar *group);

/**
 * Sets action score for a specified metric with the specified priority
 * @param cfg config file
 * @param metric metric name (or NULL for default metric)
 * @param action_name symbolic name of action
 * @param obj data to set for action
 * @return TRUE if symbol has been inserted or FALSE if action already exists with higher priority
 */
gboolean rspamd_config_set_action_score (struct rspamd_config *cfg,
										 const gchar *action_name,
										 const ucl_object_t *obj);

/**
 * Check priority and maybe disable action completely
 * @param cfg
 * @param action_name
 * @param priority
 * @return
 */
gboolean rspamd_config_maybe_disable_action (struct rspamd_config *cfg,
											 const gchar *action_name,
											 guint priority);

/**
 * Checks if a specified C or lua module is enabled or disabled in the config.
 * The logic of check is the following:
 *
 * - For C modules, we check `filters` line and enable module only if it is found there
 * - For LUA modules we check the corresponding configuration section:
 *   - if section exists, then we check `enabled` key and check its value
 *   - if section is absent, we consider module as disabled
 * - For both C and LUA modules we check if the group with the module name is disabled in the default metric
 * @param cfg config file
 * @param module_name module name
 * @return TRUE if a module is enabled
 */
gboolean rspamd_config_is_module_enabled (struct rspamd_config *cfg,
										  const gchar *module_name);

/*
 * Get action from a string
 */
gboolean rspamd_action_from_str (const gchar *data, gint *result);

/*
 * Return textual representation of action enumeration
 */
const gchar *rspamd_action_to_str (enum rspamd_action_type action);

const gchar *rspamd_action_to_str_alt (enum rspamd_action_type action);

/*
 * Resort all actions (needed to operate with thresholds)
 */
void rspamd_actions_sort (struct rspamd_config *cfg);

/**
 * Parse radix tree or radix map from ucl object
 * @param cfg configuration object
 * @param obj ucl object with parameter
 * @param target target radix tree
 * @param err error pointer
 * @return
 */
struct rspamd_radix_map_helper;

gboolean rspamd_config_radix_from_ucl (struct rspamd_config *cfg, const ucl_object_t *obj, const gchar *description,
									   struct rspamd_radix_map_helper **target, GError **err,
									   struct rspamd_worker *worker, const gchar *map_name);

/**
 * Adds new settings id to be preprocessed
 * @param cfg
 * @param name
 * @param symbols_enabled (ownership is transferred to callee)
 * @param symbols_disabled (ownership is transferred to callee)
 */
void rspamd_config_register_settings_id (struct rspamd_config *cfg,
										 const gchar *name,
										 ucl_object_t *symbols_enabled,
										 ucl_object_t *symbols_disabled,
										 enum rspamd_config_settings_policy policy);

/**
 * Convert settings name to settings id
 * @param name
 * @param namelen
 * @return
 */
guint32 rspamd_config_name_to_id (const gchar *name, gsize namelen);

/**
 * Finds settings id element and obtain reference count (must be unrefed by caller)
 * @param cfg
 * @param id
 * @return
 */
struct rspamd_config_settings_elt *rspamd_config_find_settings_id_ref (
		struct rspamd_config *cfg,
		guint32 id);

/**
 * Finds settings id element and obtain reference count (must be unrefed by callee)
 * @param cfg
 * @param id
 * @return
 */
struct rspamd_config_settings_elt *rspamd_config_find_settings_name_ref (
		struct rspamd_config *cfg,
		const gchar *name, gsize namelen);

/**
 * Returns action object by name
 * @param cfg
 * @param name
 * @return
 */
struct rspamd_action *rspamd_config_get_action (struct rspamd_config *cfg,
												const gchar *name);

struct rspamd_action *rspamd_config_get_action_by_type (struct rspamd_config *cfg,
														enum rspamd_action_type type);

int rspamd_config_ev_backend_get (struct rspamd_config *cfg);
const gchar * rspamd_config_ev_backend_to_string (int ev_backend, gboolean *effective);

struct rspamd_external_libs_ctx;

/**
 * Initialize rspamd libraries
 */
struct rspamd_external_libs_ctx *rspamd_init_libs (void);

/**
 * Reset and initialize decompressor
 * @param ctx
 */
gboolean rspamd_libs_reset_decompression (struct rspamd_external_libs_ctx *ctx);

/**
 * Reset and initialize compressor
 * @param ctx
 */
gboolean rspamd_libs_reset_compression (struct rspamd_external_libs_ctx *ctx);

/**
 * Destroy external libraries context
 */
void rspamd_deinit_libs (struct rspamd_external_libs_ctx *ctx);

/**
 * Returns TRUE if an address belongs to some local address
 */
gboolean rspamd_ip_is_local_cfg (struct rspamd_config *cfg,
		const rspamd_inet_addr_t *addr);

/**
 * Configure libraries
 */
gboolean rspamd_config_libs (struct rspamd_external_libs_ctx *ctx,
							 struct rspamd_config *cfg);

#define msg_err_config(...) rspamd_default_log_function (G_LOG_LEVEL_CRITICAL, \
        cfg->cfg_pool->tag.tagname, cfg->checksum, \
        G_STRFUNC, \
        __VA_ARGS__)
#define msg_err_config_forced(...) rspamd_default_log_function (G_LOG_LEVEL_CRITICAL|RSPAMD_LOG_FORCED, \
        cfg->cfg_pool->tag.tagname, cfg->checksum, \
        G_STRFUNC, \
        __VA_ARGS__)
#define msg_warn_config(...)   rspamd_default_log_function (G_LOG_LEVEL_WARNING, \
        cfg->cfg_pool->tag.tagname, cfg->checksum, \
        G_STRFUNC, \
        __VA_ARGS__)
#define msg_info_config(...)   rspamd_default_log_function (G_LOG_LEVEL_INFO, \
        cfg->cfg_pool->tag.tagname, cfg->checksum, \
        G_STRFUNC, \
        __VA_ARGS__)
extern guint rspamd_config_log_id;
#define msg_debug_config(...)  rspamd_conditional_debug_fast (NULL, NULL, \
        rspamd_config_log_id, "config", cfg->checksum, \
        G_STRFUNC, \
        __VA_ARGS__)

#ifdef  __cplusplus
}
#endif

#endif /* ifdef CFG_FILE_H */
