#
# Rspamd - rapid antispam system
#
# Cmake configuration file
#

############################# INITIAL SECTION #############################################
CMAKE_MINIMUM_REQUIRED(VERSION 3.12 FATAL_ERROR)

SET(RSPAMD_VERSION_MAJOR 2)
SET(RSPAMD_VERSION_MINOR 8)

# Keep two digits all the time
SET(RSPAMD_VERSION_MAJOR_NUM ${RSPAMD_VERSION_MAJOR}0)
SET(RSPAMD_VERSION_MINOR_NUM ${RSPAMD_VERSION_MINOR}0)

IF(GIT_ID)
	SET(GIT_VERSION 1)
	SET(RSPAMD_ID "${GIT_ID}")
ENDIF()

SET(RSPAMD_VERSION         "${RSPAMD_VERSION_MAJOR}.${RSPAMD_VERSION_MINOR}")

PROJECT(rspamd VERSION "${RSPAMD_VERSION}" LANGUAGES C CXX ASM)

CMAKE_POLICY(SET CMP0075 NEW)

# This is supported merely with cmake 3.1
SET(CMAKE_C_STANDARD 11)
SET(CMAKE_CXX_STANDARD 17)
SET(CMAKE_C_STANDARD_REQUIRED ON)
SET(CMAKE_CXX_STANDARD_REQUIRED ON)
LIST(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/")

SET(RSPAMD_MASTER_SITE_URL "https://rspamd.com")

IF(NOT RSPAMD_USER)
	SET(RSPAMD_USER "nobody")
	SET(RSPAMD_GROUP "nobody")
ENDIF(NOT RSPAMD_USER)

# Default for SysV Init
SET(RSPAMD_WORKER_NORMAL "*:11333")
SET(RSPAMD_WORKER_CONTROLLER "*:11334")

############################# OPTIONS SECTION #############################################
OPTION(ENABLE_LUAJIT       "Link with libluajit [default: ON]"                  ON)
OPTION(ENABLE_URL_INCLUDE  "Enable urls in ucl includes (requires libcurl or libfetch) [default: OFF]" OFF)
OPTION(NO_SHARED           "Build internal libs static [default: ON]"          ON)
OPTION(INSTALL_WEBUI       "Install web interface [default: ON]"                ON)
OPTION(WANT_SYSTEMD_UNITS  "Install systemd unit files on Linux [default: OFF]" OFF)
OPTION(ENABLE_SNOWBALL     "Enable snowball stemmer [default: ON]"              ON)
OPTION(ENABLE_CLANG_PLUGIN "Enable clang static analysing plugin [default: OFF]" OFF)
OPTION(ENABLE_PCRE2        "Enable pcre2 instead of pcre  [default: OFF]"         OFF)
OPTION(ENABLE_JEMALLOC     "Build rspamd with jemalloc allocator  [default: OFF]" OFF)
OPTION(ENABLE_UTILS        "Build rspamd internal utils [default: OFF]" OFF)
OPTION(ENABLE_LIBUNWIND    "Use libunwind to print crash traces [default: OFF]" OFF)
OPTION(ENABLE_LUA_TRACE    "Trace all Lua C API invocations [default: OFF]" OFF)
OPTION(ENABLE_LUA_REPL     "Enables Lua repl (requires C++11 compiler) [default: ON]" ON)
OPTION(SYSTEM_ZSTD         "Use system zstd instead of bundled one [default: OFF]" OFF)

############################# INCLUDE SECTION #############################################

INCLUDE(CheckIncludeFiles)
INCLUDE(CheckFunctionExists)
INCLUDE(CheckSymbolExists)
INCLUDE(CheckCSourceCompiles)
INCLUDE(CheckCSourceRuns)
INCLUDE(CheckLibraryExists)
INCLUDE(CheckCCompilerFlag)
INCLUDE(CMakeParseArguments)
INCLUDE(FindArch)
INCLUDE(AsmOp)
INCLUDE(FindRagel)
INCLUDE(ProcessPackage)

IF(NOT RAGEL_FOUND)
	MESSAGE(FATAL_ERROR "Ragel is required to build rspamd")
ENDIF()

FIND_PACKAGE(PkgConfig REQUIRED)
FIND_PACKAGE(Perl REQUIRED)

INCLUDE(Toolset)
INCLUDE(Sanitizer)

INCLUDE(ArchDep)
INCLUDE(Paths)

IF(ENABLE_PCRE2 MATCHES "ON")
	SET(WITH_PCRE2 1)
	# For utf8 API
	LIST(APPEND CMAKE_REQUIRED_DEFINITIONS "-DPCRE2_CODE_UNIT_WIDTH=8")
ENDIF()
############################# CONFIG SECTION #############################################
# Initial set

# Prefer local include dirs to system ones
INCLUDE_DIRECTORIES("${CMAKE_SOURCE_DIR}/"
		"${CMAKE_SOURCE_DIR}/src"
		"${CMAKE_SOURCE_DIR}/src/libutil"
		"${CMAKE_SOURCE_DIR}/src/libserver"
		"${CMAKE_SOURCE_DIR}/src/libmime"
		"${CMAKE_SOURCE_DIR}/src/libstat"
		"${CMAKE_SOURCE_DIR}/src/libcryptobox"
		"${CMAKE_SOURCE_DIR}/contrib/libucl"
		"${CMAKE_SOURCE_DIR}/contrib/replxx/include"
		"${CMAKE_SOURCE_DIR}/contrib/uthash"
		"${CMAKE_SOURCE_DIR}/contrib/http-parser"
		"${CMAKE_SOURCE_DIR}/contrib/fpconv"
		"${CMAKE_SOURCE_DIR}/contrib/libottery"
		"${CMAKE_SOURCE_DIR}/contrib/xxhash"
		"${CMAKE_SOURCE_DIR}/contrib/cdb"
		"${CMAKE_SOURCE_DIR}/contrib/snowball/include"
		"${CMAKE_SOURCE_DIR}/contrib/librdns"
		"${CMAKE_SOURCE_DIR}/contrib/aho-corasick"
		"${CMAKE_SOURCE_DIR}/contrib/lc-btrie"
		"${CMAKE_SOURCE_DIR}/contrib/lua-lpeg"
		"${CMAKE_SOURCE_DIR}/contrib/frozen/include"
		"${CMAKE_SOURCE_DIR}/contrib/fmt/include"
		"${CMAKE_SOURCE_DIR}/contrib/doctest"
		"${CMAKE_SOURCE_DIR}/contrib/fu2/include"
		"${CMAKE_BINARY_DIR}/src" #Stored in the binary dir
		"${CMAKE_BINARY_DIR}/src/libcryptobox")

SET(TAR "tar")
INCLUDE(OSDep)

# Now find libraries and headers
LIST(APPEND RSPAMD_REQUIRED_LIBRARIES "m")
LIST(APPEND RSPAMD_REQUIRED_LIBRARIES "pthread")

IF(ENABLE_LUAJIT MATCHES "ON")
	ProcessPackage(LIBLUAJIT LIBRARY	"luajit"
										"luajit-2.1"
										"luajit2.1"
										"luajit-2.0"
										"luajit2.0"
										"luajit-5.1"
			INCLUDE luajit.h INCLUDE_SUFFIXES
										"include/luajit-2.1"
										"include/luajit-2.0"
										"include/luajit"
			ROOT ${LUA_ROOT}
			MODULES luajit)
	SET(WITH_LUAJIT 1)
ELSE(ENABLE_LUAJIT MATCHES "ON")

	ProcessPackage(LIBLUA LIBRARY	"lua"
			"lua-5.3"
			LIB_SUFFIXES	"lua5.3"
			INCLUDE lua.h INCLUDE_SUFFIXES
			"include/lua-5.3"
			"include/lua5.3"
			"include/lua53"
			"include/lua"
			ROOT ${LUA_ROOT}
			MODULES lua53
			OPTIONAL)

	IF (NOT WITH_LIBLUA)
		ProcessPackage(LIBLUA LIBRARY	"lua"
				"lua-5.4"
				LIB_SUFFIXES	"lua5.4"
				INCLUDE lua.h INCLUDE_SUFFIXES
				"include/lua-5.4"
				"include/lua5.4"
				"include/lua54"
				"include/lua"
				ROOT ${LUA_ROOT}
				MODULES lua54
				OPTIONAL)
		IF (NOT WITH_LIBLUA)
			ProcessPackage(LIBLUA LIBRARY	"lua"
					"lua-5.2"
					LIB_SUFFIXES	"lua5.2"
					INCLUDE lua.h INCLUDE_SUFFIXES
					"include/lua-5.2"
					"include/lua5.2"
					"include/lua52"
					"include/lua"
					ROOT ${LUA_ROOT}
					MODULES lua52
					OPTIONAL)

			IF (NOT WITH_LIBLUA)
				ProcessPackage(LIBLUA LIBRARY	"lua"
						"lua-5.1"
						INCLUDE lua.h INCLUDE_SUFFIXES
						"include/lua-5.1"
						"include/lua5.1"
						"include/lua51"
						"include/lua"
						ROOT ${LUA_ROOT}
						MODULES lua51)
			ENDIF()
		ENDIF()
	ENDIF()
ENDIF(ENABLE_LUAJIT MATCHES "ON")

IF(ENABLE_JEMALLOC MATCHES "ON" AND NOT SANITIZE)
	ProcessPackage(JEMALLOC LIBRARY jemalloc_pic jemalloc INCLUDE jemalloc.h INCLUDE_SUFFIXES include/jemalloc
		ROOT ${JEMALLOC_ROOT_DIR})
	SET(WITH_JEMALLOC "1")
ENDIF()

IF(ENABLE_LIBUNWIND MATCHES "ON")
	ProcessPackage(LIBUNWIND LIBRARY unwind INCLUDE libunwind.h INCLUDE_SUFFIXES include/libunwind
			ROOT ${LIBUNWIND_ROOT_DIR} MODULES libunwind)
	SET(WITH_LIBUNWIND "1")
ENDIF()

ProcessPackage(GLIB2 LIBRARY glib-2.0 INCLUDE glib.h
	INCLUDE_SUFFIXES include/glib include/glib-2.0
	ROOT ${GLIB_ROOT_DIR} MODULES glib-2.0>=2.28)

IF(ENABLE_PCRE2 MATCHES "ON")
	ProcessPackage(PCRE LIBRARY pcre2 pcre2-8 INCLUDE pcre2.h INCLUDE_SUFFIXES include/pcre2
		ROOT ${PCRE_ROOT_DIR} MODULES pcre2 pcre2-8 libpcre2 libpcre2-8)
ELSE()
	ProcessPackage(PCRE LIBRARY pcre INCLUDE pcre.h INCLUDE_SUFFIXES include/pcre
		ROOT ${PCRE_ROOT_DIR} MODULES pcre libpcre pcre3 libpcre3)
ENDIF()

ProcessPackage(SQLITE3 LIBRARY sqlite3 INCLUDE sqlite3.h INCLUDE_SUFFIXES include/sqlite3 include/sqlite
	ROOT ${SQLITE3_ROOT_DIR} MODULES sqlite3 sqlite)
ProcessPackage(ICUDATA LIBRARY icudata INCLUDE unicode/ucnv.h
	ROOT ${ICU_ROOT_DIR} MODULES icu-uc)
ProcessPackage(ICUC LIBRARY icuuc INCLUDE unicode/ucnv.h
	ROOT ${ICU_ROOT_DIR} MODULES icu-uc)
ProcessPackage(ICUIO LIBRARY icuio INCLUDE unicode/ucnv.h
		ROOT ${ICU_ROOT_DIR} MODULES icu-io)
ProcessPackage(ICUI18N LIBRARY icui18n INCLUDE unicode/ucnv.h
	ROOT ${ICU_ROOT_DIR} MODULES icu-i18n)
ProcessPackage(LIBCRYPT LIBRARY crypto INCLUDE openssl/evp.h
	ROOT ${OPENSSL_ROOT_DIR} MODULES openssl libcrypt)
ProcessPackage(LIBSSL LIBRARY ssl INCLUDE openssl/ssl.h
	ROOT ${OPENSSL_ROOT_DIR} MODULES openssl libssl)
ProcessPackage(LIBZ LIBRARY z INCLUDE zlib.h INCLUDE_SUFFIXES include/zlib
		ROOT ${LIBZ_ROOT_DIR} MODULES z)
ProcessPackage(SODIUM LIBRARY sodium INCLUDE sodium.h
		INCLUDE_SUFFIXES include/libsodium include/sodium
		ROOT ${LIBSODIUM_ROOT_DIR} MODULES libsodium>=1.0.0)

include (CompilerWarnings)
include (Hyperscan)
include (Openblas)

IF(ENABLE_LUA_TRACE)
	SET(WITH_LUA_TRACE 1)
ENDIF(ENABLE_LUA_TRACE)

SET(CMAKE_C_FLAGS "${CMAKE_C_OPT_FLAGS} ${CMAKE_C_FLAGS}")
SET(CMAKE_CXX_FLAGS "${CMAKE_C_OPT_FLAGS} ${CMAKE_CXX_FLAGS}")

ADD_DEFINITIONS(-DHAVE_CONFIG_H)
ADD_DEFINITIONS(-DDOCTEST_CONFIG_NO_MULTI_LANE_ATOMICS)
# Workaround for https://github.com/onqtam/doctest/issues/356
ADD_DEFINITIONS(-DDOCTEST_CONFIG_USE_STD_HEADERS)
ADD_DEFINITIONS(-DU_CHARSET_IS_UTF8)

# Check platform specific includes
CHECK_INCLUDE_FILES(sys/types.h HAVE_SYS_TYPES_H)
CHECK_INCLUDE_FILES(sys/time.h  HAVE_SYS_TIME_H)
CHECK_INCLUDE_FILES(sys/uio.h   HAVE_SYS_UIO_H)

CHECK_INCLUDE_FILES(fcntl.h     HAVE_FCNTL_H)
CHECK_INCLUDE_FILES(math.h      HAVE_MATH_H)
CHECK_INCLUDE_FILES(stdio.h     HAVE_STDIO_H)
CHECK_INCLUDE_FILES(stdlib.h    HAVE_STDLIB_H)
CHECK_INCLUDE_FILES(string.h    HAVE_STRING_H)
CHECK_INCLUDE_FILES(strings.h   HAVE_STRINGS_H)
CHECK_INCLUDE_FILES(time.h      HAVE_TIME_H)
CHECK_INCLUDE_FILES(unistd.h    HAVE_UNISTD_H)
CHECK_INCLUDE_FILES(stdint.h  HAVE_STDINT_H)
CHECK_INCLUDE_FILES(inttypes.h  HAVE_INTTYPES_H)
CHECK_INCLUDE_FILES(stdbool.h  HAVE_STDBOOL_H)
CHECK_INCLUDE_FILES(endian.h  HAVE_ENDIAN_H)
CHECK_INCLUDE_FILES(sys/endian.h  HAVE_SYS_ENDIAN_H)
CHECK_INCLUDE_FILES(machine/endian.h  HAVE_MACHINE_ENDIAN_H)
CHECK_INCLUDE_FILES(sys/queue.h  HAVE_SYS_QUEUE_H)
CHECK_INCLUDE_FILES(sys/socket.h  HAVE_SYS_SOCKET_H)
CHECK_INCLUDE_FILES(sys/mman.h  HAVE_SYS_MMAN_H)
CHECK_INCLUDE_FILES(sys/un.h  HAVE_SYS_UN_H)
CHECK_INCLUDE_FILES(sys/stat.h  HAVE_SYS_STAT_H)
CHECK_INCLUDE_FILES(sys/wait.h  HAVE_SYS_WAIT_H)
CHECK_INCLUDE_FILES(sys/param.h  HAVE_SYS_PARAM_H)
CHECK_INCLUDE_FILES(sys/cdefs.h  HAVE_SYS_CDEFS_H)
CHECK_INCLUDE_FILES(sys/file.h  HAVE_SYS_FILE_H)
CHECK_INCLUDE_FILES(sys/utsname.h  HAVE_SYS_UTSNAME_H)
CHECK_INCLUDE_FILES(sys/resource.h  HAVE_SYS_RESOURCE_H)
CHECK_INCLUDE_FILES(netinet/in.h  HAVE_NETINET_IN_H)
CHECK_INCLUDE_FILES(netinet/tcp.h  HAVE_NETINET_TCP_H)
CHECK_INCLUDE_FILES(arpa/inet.h  HAVE_ARPA_INET_H)
CHECK_INCLUDE_FILES(netdb.h  HAVE_NETDB_H)
CHECK_INCLUDE_FILES(syslog.h HAVE_SYSLOG_H)
CHECK_INCLUDE_FILES(siginfo.h HAVE_SIGINFO_H)
CHECK_INCLUDE_FILES(locale.h HAVE_LOCALE_H)
CHECK_INCLUDE_FILES(libgen.h HAVE_LIBGEN_H)
CHECK_INCLUDE_FILES(search.h HAVE_SEARCH_H)
CHECK_INCLUDE_FILES(pwd.h HAVE_PWD_H)
CHECK_INCLUDE_FILES(grp.h HAVE_GRP_H)
CHECK_INCLUDE_FILES(glob.h HAVE_GLOB_H)
CHECK_INCLUDE_FILES(poll.h HAVE_POLL_H)
CHECK_INCLUDE_FILES(readpassphrase.h HAVE_READPASSPHRASE_H)
CHECK_INCLUDE_FILES(termios.h HAVE_TERMIOS_H)
CHECK_INCLUDE_FILES(paths.h HAVE_PATHS_H)
CHECK_INCLUDE_FILES(ctype.h HAVE_CTYPE_H)
CHECK_INCLUDE_FILES(unistd.h HAVE_UNISTD_H)
CHECK_INCLUDE_FILES(cpuid.h HAVE_CPUID_H)
CHECK_INCLUDE_FILES(dirent.h HAVE_DIRENT_H)
CHECK_INCLUDE_FILES(stropts.h HAVE_STROPS_H)
CHECK_INCLUDE_FILES(sys/ioctl.h HAVE_SYS_IOCTL_H)
CHECK_INCLUDE_FILES(ucontext.h HAVE_UCONTEXT_H)
CHECK_INCLUDE_FILES(sys/ucontext.h HAVE_SYS_UCONTEXT_H) # OSX specific

# Check platform API
CHECK_FUNCTION_EXISTS(setproctitle HAVE_SETPROCTITLE)
CHECK_FUNCTION_EXISTS(getpagesize HAVE_GETPAGESIZE)
CHECK_FUNCTION_EXISTS(nanosleep HAVE_NANOSLEEP)
CHECK_FUNCTION_EXISTS(vfork HAVE_VFORK)
CHECK_FUNCTION_EXISTS(wait4 HAVE_WAIT4)
CHECK_FUNCTION_EXISTS(waitpid HAVE_WAITPID)
CHECK_FUNCTION_EXISTS(flock HAVE_FLOCK)
CHECK_LIBRARY_EXISTS(m tanhl "" HAVE_TANHL)
CHECK_LIBRARY_EXISTS(m tanh "" HAVE_TANH)
CHECK_LIBRARY_EXISTS(m expl "" HAVE_EXPL)
CHECK_LIBRARY_EXISTS(m exp2l "" HAVE_EXP2L)
CHECK_FUNCTION_EXISTS(sendfile HAVE_SENDFILE)
CHECK_FUNCTION_EXISTS(mkstemp HAVE_MKSTEMP)
CHECK_FUNCTION_EXISTS(setitimer HAVE_SETITIMER)
CHECK_FUNCTION_EXISTS(inet_pton HAVE_INET_PTON)
CHECK_FUNCTION_EXISTS(clock_gettime HAVE_CLOCK_GETTIME)
CHECK_C_SOURCE_COMPILES(
		"#include <time.h>
		extern char *tzname[2];
		extern long timezone;
		extern int daylight;
	int main(int argc, char** argv) {
		tzset();
		return timezone;
	}" HAVE_SANE_TZSET)

# Check macros
CHECK_SYMBOL_EXISTS(PATH_MAX limits.h HAVE_PATH_MAX)
CHECK_SYMBOL_EXISTS(MAXPATHLEN sys/param.h HAVE_MAXPATHLEN)
CHECK_SYMBOL_EXISTS(MAP_SHARED sys/mman.h HAVE_MMAP_SHARED)
CHECK_SYMBOL_EXISTS(MAP_ANON sys/mman.h HAVE_MMAP_ANON)
CHECK_SYMBOL_EXISTS(MAP_NOCORE sys/mman.h HAVE_MMAP_NOCORE)
CHECK_SYMBOL_EXISTS(O_DIRECT fcntl.h HAVE_O_DIRECT)
CHECK_SYMBOL_EXISTS(IPV6_V6ONLY "sys/socket.h;netinet/in.h" HAVE_IPV6_V6ONLY)
CHECK_SYMBOL_EXISTS(posix_fadvise fcntl.h HAVE_FADVISE)
CHECK_SYMBOL_EXISTS(posix_fallocate fcntl.h HAVE_POSIX_FALLOCATE)
CHECK_SYMBOL_EXISTS(fallocate fcntl.h HAVE_FALLOCATE)
CHECK_SYMBOL_EXISTS(fdatasync unistd.h HAVE_FDATASYNC)
CHECK_SYMBOL_EXISTS(_SC_NPROCESSORS_ONLN unistd.h HAVE_SC_NPROCESSORS_ONLN)
CHECK_SYMBOL_EXISTS(setbit sys/param.h PARAM_H_HAS_BITSET)
CHECK_SYMBOL_EXISTS(getaddrinfo "sys/types.h;sys/socket.h;netdb.h" HAVE_GETADDRINFO)
CHECK_SYMBOL_EXISTS(sched_yield "sched.h" HAVE_SCHED_YIELD)
CHECK_SYMBOL_EXISTS(__get_cpuid "cpuid.h" HAVE_GET_CPUID)
CHECK_SYMBOL_EXISTS(nftw "sys/types.h;ftw.h" HAVE_NFTW)
CHECK_SYMBOL_EXISTS(memrchr "string.h" HAVE_MEMRCHR)
IF(ENABLE_PCRE2 MATCHES "ON")
	LIST(APPEND CMAKE_REQUIRED_INCLUDES "${PCRE_INCLUDE}")
	CHECK_SYMBOL_EXISTS(PCRE2_CONFIG_JIT "pcre2.h" HAVE_PCRE_JIT)
ELSE()
	LIST(APPEND CMAKE_REQUIRED_INCLUDES "${PCRE_INCLUDE}")
	CHECK_SYMBOL_EXISTS(PCRE_CONFIG_JIT "pcre.h" HAVE_PCRE_JIT)
ENDIF()
CHECK_SYMBOL_EXISTS(SOCK_SEQPACKET "sys/types.h;sys/socket.h" HAVE_SOCK_SEQPACKET)
CHECK_SYMBOL_EXISTS(I_SETSIG "sys/types.h;sys/ioctl.h" HAVE_SETSIG)
CHECK_SYMBOL_EXISTS(O_ASYNC "sys/types.h;sys/fcntl.h" HAVE_OASYNC)
CHECK_SYMBOL_EXISTS(O_NOFOLLOW "sys/types.h;sys/fcntl.h" HAVE_ONOFOLLOW)
CHECK_SYMBOL_EXISTS(O_CLOEXEC "sys/types.h;sys/fcntl.h" HAVE_OCLOEXEC)

# OpenSSL specific stuff
LIST(APPEND CMAKE_REQUIRED_INCLUDES "${LIBSSL_INCLUDE}")
IF(LIBCRYPT_LIBRARY_PATH)
	SET(CMAKE_REQUIRED_LIBRARIES "${CMAKE_REQUIRED_LIBRARIES};-L${LIBCRYPT_LIBRARY_PATH};${LIBCRYPT_LIBRARY}")
	SET(CMAKE_REQUIRED_LIBRARIES "${CMAKE_REQUIRED_LIBRARIES};-L${LIBSSL_LIBRARY_PATH};${LIBSSL_LIBRARY}")
ELSE()
	SET(CMAKE_REQUIRED_LIBRARIES "${CMAKE_REQUIRED_LIBRARIES};-lcrypt;-lssl")
ENDIF()

CHECK_SYMBOL_EXISTS(SSL_set_tlsext_host_name "openssl/ssl.h" HAVE_SSL_TLSEXT_HOSTNAME)
CHECK_SYMBOL_EXISTS(FIPS_mode "openssl/crypto.h" HAVE_FIPS_MODE)

CHECK_SYMBOL_EXISTS(dirfd "sys/types.h;unistd.h;dirent.h" HAVE_DIRFD)
CHECK_SYMBOL_EXISTS(fpathconf "sys/types.h;unistd.h" HAVE_FPATHCONF)
CHECK_SYMBOL_EXISTS(sigaltstack "signal.h" HAVE_SIGALTSTACK)
CHECK_SYMBOL_EXISTS(open_memstream "stdio.h" HAVE_OPENMEMSTREAM)
CHECK_SYMBOL_EXISTS(fmemopen "stdio.h" HAVE_FMEMOPEN)
CHECK_SYMBOL_EXISTS(clock_getcpuclockid "sys/types.h;time.h" HAVE_CLOCK_GETCPUCLOCKID)
CHECK_SYMBOL_EXISTS(RUSAGE_SELF "sys/types.h;sys/resource.h" HAVE_RUSAGE_SELF)

IF(ENABLE_PCRE2 MATCHES "ON")
	IF(HAVE_PCRE_JIT)
		SET(HAVE_PCRE_JIT_FAST 1)
	ENDIF()
ELSE()
	LIST(APPEND CMAKE_REQUIRED_INCLUDES "${PCRE_INCLUDE}")
	IF(PCRE_LIBRARY_PATH)
		SET(CMAKE_REQUIRED_LIBRARIES "${CMAKE_REQUIRED_LIBRARIES};-L${PCRE_LIBRARY_PATH};${PCRE_LIBRARY}")
	ELSE(PCRE_LIBRARY_PATH)
		SET(CMAKE_REQUIRED_LIBRARIES "${CMAKE_REQUIRED_LIBRARIES};-lpcre")
	ENDIF(PCRE_LIBRARY_PATH)
# Some PCRE implementations are lacking of pcre_jit_exec fast path
SET(_PCRE_FAST_TEST "
#include \"pcre.h\"
int main (void)
{
	int rc;
	int ovector[30];
	pcre *re;
	pcre_extra *extra;
	pcre_jit_stack *jit_stack;

	re = pcre_compile(\"abc\", 0, NULL, NULL, NULL);
	extra = pcre_study(re, PCRE_STUDY_JIT_COMPILE, NULL);
	jit_stack = pcre_jit_stack_alloc(32*1024, 512*1024);
	pcre_assign_jit_stack(extra, NULL, jit_stack);
	rc = pcre_jit_exec(re, extra, \"abc\", 3, 0, 0, ovector, 30, jit_stack);

	return rc;
}
")
CHECK_C_SOURCE_COMPILES("${_PCRE_FAST_TEST}" HAVE_PCRE_JIT_FAST)
IF(HAVE_PCRE_JIT_FAST)
	MESSAGE(STATUS "pcre_jit_exec is supported")
ELSE(HAVE_PCRE_JIT_FAST)
	MESSAGE(STATUS "pcre_jit_exec is -NOT- supported")
ENDIF(HAVE_PCRE_JIT_FAST)
ENDIF()

FILE(WRITE ${CMAKE_BINARY_DIR}/pthread_setpshared.c "
#include <pthread.h>
#include <stdlib.h>
int main (void)
{
	pthread_mutexattr_t mattr;
	if (pthread_mutexattr_init(&mattr) != 0) return 0;
	if (pthread_mutexattr_setpshared(&mattr, PTHREAD_PROCESS_SHARED) != 0) return 0;
	if (pthread_mutexattr_setrobust(&mattr, PTHREAD_MUTEX_ROBUST) != 0) return 0;
	return 1;
}
")
TRY_RUN(_CAN_RUN _CAN_COMPILE
	"${CMAKE_BINARY_DIR}" "${CMAKE_BINARY_DIR}/pthread_setpshared.c"
	CMAKE_FLAGS CMAKE_C_FLAGS="-pthread")
IF(_CAN_RUN EQUAL 1)
	SET(HAVE_PTHREAD_PROCESS_SHARED 1 CACHE INTERNAL "")
ENDIF(_CAN_RUN EQUAL 1)
IF(HAVE_PTHREAD_PROCESS_SHARED)
	MESSAGE(STATUS "pthread_mutexattr_setpshared is supported")
ELSE(HAVE_PTHREAD_PROCESS_SHARED)
	MESSAGE(STATUS "pthread_mutexattr_setpshared is -NOT- supported")
ENDIF(HAVE_PTHREAD_PROCESS_SHARED)

IF(NOT HAVE_GETADDRINFO)
	MESSAGE(FATAL_ERROR "Your system does not support getaddrinfo call, please consider upgrading it to run rspamd")
ENDIF(NOT HAVE_GETADDRINFO)
IF(HAVE_SIGINFO_H)
	CHECK_SYMBOL_EXISTS(SA_SIGINFO "signal.h;siginfo.h" HAVE_SA_SIGINFO)
ELSE(HAVE_SIGINFO_H)
	CHECK_SYMBOL_EXISTS(SA_SIGINFO "signal.h" HAVE_SA_SIGINFO)
ENDIF(HAVE_SIGINFO_H)

IF(NOT CMAKE_SYSTEM_NAME STREQUAL "SunOS")
IF(HAVE_CLOCK_GETTIME)
	CHECK_SYMBOL_EXISTS(CLOCK_PROCESS_CPUTIME_ID time.h HAVE_CLOCK_PROCESS_CPUTIME_ID)
	CHECK_SYMBOL_EXISTS(CLOCK_VIRTUAL time.h HAVE_CLOCK_VIRTUAL)
ELSE(HAVE_CLOCK_GETTIME)
	CHECK_INCLUDE_FILES(sys/timeb.h HAVE_SYS_TIMEB_H)
ENDIF(HAVE_CLOCK_GETTIME)

# Check asm pause instruction
CHECK_C_SOURCE_COMPILES ("#include <sys/types.h>
						  int main (int argc, char **argv) {
							__asm __volatile(\"pause\");
							return 0;
						  }" HAVE_ASM_PAUSE)
ENDIF(NOT CMAKE_SYSTEM_NAME STREQUAL "SunOS")

CHECK_C_SOURCE_RUNS("
#include <stdbool.h>
int main(int argc, char **argv) {
        int a = 0, b = 0;
        if (__atomic_compare_exchange_n(&a, &b, 1, false, __ATOMIC_RELEASE, __ATOMIC_RELAXED)) {
                return 0;
        }
        return -1;
}
" HAVE_ATOMIC_BUILTINS)

IF(NOT HAVE_ATOMIC_BUILTINS)
	MESSAGE(STATUS "atomic builtins are -NOT- supported")
ELSE()
	MESSAGE(STATUS "atomic builtins are supported")
ENDIF()

CHECK_C_SOURCE_RUNS("
#include <x86intrin.h>
int main(int argc, char **argv) {
        __builtin_ia32_lfence ();
        if (__builtin_ia32_rdtsc()) {
                return 0;
        }
        return -1;
}
" HAVE_RDTSC)

IF(NOT HAVE_RDTSC)
	MESSAGE(STATUS "rdtsc intrinsic is -NOT- supported")
ELSE()
	MESSAGE(STATUS "rdtsc intrinsic is supported")
ENDIF()

IF(CMAKE_SYSTEM_NAME STREQUAL "Linux")
	# In linux, we need to mount /run/shm to test which could be unavailable
	# on a build system. On the other hand, we know that linux has stupid
	# but compatible shmem support, so we assume this macro as true
	SET(HAVE_SANE_SHMEM 1)
	CHECK_C_SOURCE_COMPILES ("#define _GNU_SOURCE
						  #include <sys/socket.h>
						  int main (int argc, char **argv) {
							return ((int*)(&recvmmsg))[argc];
						  }" HAVE_RECVMMSG)
ELSE()
	CHECK_C_SOURCE_RUNS("
	#include <sys/mman.h>
	#include <fcntl.h>
	#include <unistd.h>
	#define TEST_NAME \"/test-shmem-work\"
	int
	main (int argc, char **argv)
	{
	  int fd;

	  fd = shm_open (TEST_NAME, O_RDWR | O_CREAT | O_EXCL, 00600);
	  if (fd == -1) {
	    return -1;
	  }
	  if (ftruncate (fd, 100) == -1) {
	    shm_unlink (TEST_NAME);
	    close (fd);
	    return -1;
	  }

	  if (ftruncate (fd, 200) == -1) {
	    shm_unlink (TEST_NAME);
	    close (fd);
	    return -1;
	  }
	  if (ftruncate (fd, 300) == -1) {
	    shm_unlink (TEST_NAME);
	    close (fd);
	    return -1;
	  }

	  close (fd);
	  shm_unlink (TEST_NAME);
	  return 0;
	}
	" HAVE_SANE_SHMEM)
	IF(NOT HAVE_SANE_SHMEM)
		MESSAGE(STATUS "shmem support is NOT compatible with POSIX")
	ELSE()
		MESSAGE(STATUS "shmem support is compatible with POSIX")
	ENDIF()
ENDIF()

# Check queue.h compatibility
IF(NOT HAVE_COMPATIBLE_QUEUE_H)
	INCLUDE_DIRECTORIES(compat)
ENDIF(NOT HAVE_COMPATIBLE_QUEUE_H)

IF(ENABLE_URL_INCLUDE MATCHES "ON")
	FIND_LIBRARY(LIBFETCH_LIBRARY HINTS "${RSPAMD_SEARCH_PATH}"
					NAMES fetch PATHS	PATH_SUFFIXES lib64 lib
					PATHS ${RSPAMD_DEFAULT_LIBRARY_PATHS}
					DOC "Path where the libfetch library can be found")
	IF(LIBFETCH_LIBRARY)
		FIND_FILE(HAVE_FETCH_H HINTS "${RSPAMD_SEARCH_PATH}"
			NAMES fetch.h
			PATH_SUFFIXES include
			PATHS ${RSPAMD_DEFAULT_INCLUDE_PATHS}
					DOC "Path to libfetch header")
	ELSE(LIBFETCH_LIBRARY)
		# Try to find libcurl
		ProcessPackage(CURL LIBRARY curl INCLUDE curl.h INCLUDE_SUFFIXES include/curl
			ROOT ${CURL_ROOT})
		IF(NOT WITH_CURL)
			MESSAGE(WARNING "Neither libcurl nor libfetch were found, no support of URL includes in configuration")
		ENDIF(NOT WITH_CURL)
	ENDIF(LIBFETCH_LIBRARY)
ENDIF(ENABLE_URL_INCLUDE MATCHES "ON")

IF(NOT DESTDIR)
	SET(DESTDIR $ENV{DESTDIR})
ENDIF(NOT DESTDIR)


################################ SUBDIRS SECTION ###########################
ADD_SUBDIRECTORY(contrib/hiredis)
SET(WITH_HIREDIS 1)
INCLUDE_DIRECTORIES(BEFORE "${CMAKE_SOURCE_DIR}/contrib/hiredis")

LIST(APPEND RSPAMD_REQUIRED_LIBRARIES "${CMAKE_REQUIRED_LIBRARIES}")
IF(HAVE_FETCH_H)
	LIST(APPEND RSPAMD_REQUIRED_LIBRARIES fetch)
ENDIF(HAVE_FETCH_H)
IF(WITH_DB)
	LIST(APPEND RSPAMD_REQUIRED_LIBRARIES db)
ENDIF(WITH_DB)

LIST(APPEND RSPAMD_REQUIRED_LIBRARIES "${LUA_LIBRARY}")
LIST(APPEND RSPAMD_REQUIRED_LIBRARIES ucl)
LIST(APPEND RSPAMD_REQUIRED_LIBRARIES rdns)
LIST(APPEND RSPAMD_REQUIRED_LIBRARIES ottery)
LIST(APPEND RSPAMD_REQUIRED_LIBRARIES xxhash)

IF(GLIB_COMPAT)
	LIST(APPEND RSPAMD_REQUIRED_LIBRARIES glibadditions)
ENDIF(GLIB_COMPAT)


ADD_SUBDIRECTORY(contrib/xxhash)
ADD_SUBDIRECTORY(contrib/cdb)
ADD_SUBDIRECTORY(contrib/http-parser)
ADD_SUBDIRECTORY(contrib/fpconv)
ADD_SUBDIRECTORY(contrib/lc-btrie)
ADD_SUBDIRECTORY(contrib/libottery)
IF(SYSTEM_ZSTD MATCHES "OFF")
	ADD_SUBDIRECTORY(contrib/zstd)
ELSE()
	ProcessPackage(LIBZSTD LIBRARY zstd INCLUDE zstd.h
		ROOT ${LIBZSTD_ROOT_DIR} MODULES zstd)
	ADD_DEFINITIONS(-DSYS_ZSTD)
ENDIF()
IF(ENABLE_SNOWBALL MATCHES "ON")
	ADD_SUBDIRECTORY(contrib/snowball)
	SET(WITH_SNOWBALL 1)
ENDIF()
ADD_SUBDIRECTORY(contrib/libucl)
ADD_SUBDIRECTORY(contrib/librdns)
ADD_SUBDIRECTORY(contrib/aho-corasick)
ADD_SUBDIRECTORY(contrib/lua-lpeg)
ADD_SUBDIRECTORY(contrib/t1ha)
ADD_SUBDIRECTORY(contrib/libev)
ADD_SUBDIRECTORY(contrib/kann)
ADD_SUBDIRECTORY(contrib/fastutf8)
ADD_SUBDIRECTORY(contrib/google-ced)
ADD_SUBDIRECTORY(contrib/fmt)
ADD_SUBDIRECTORY(contrib/doctest)

IF (NOT WITH_LUAJIT)
	ADD_SUBDIRECTORY(contrib/lua-bit)
ENDIF()

IF (ENABLE_LUA_REPL MATCHES "ON")
	ADD_SUBDIRECTORY(contrib/replxx)
	SET(WITH_LUA_REPL 1)
	LIST(APPEND RSPAMD_REQUIRED_LIBRARIES rspamd-replxx)
ENDIF()

IF (ENABLE_SNOWBALL MATCHES "ON")
	LIST(APPEND RSPAMD_REQUIRED_LIBRARIES stemmer)
ENDIF()
LIST(APPEND RSPAMD_REQUIRED_LIBRARIES rspamd-hiredis)

LIST(APPEND RSPAMD_REQUIRED_LIBRARIES rspamd-actrie)
LIST(APPEND RSPAMD_REQUIRED_LIBRARIES rspamd-t1ha)
LIST(APPEND RSPAMD_REQUIRED_LIBRARIES rspamd-ev)
LIST(APPEND RSPAMD_REQUIRED_LIBRARIES rspamd-kann)
LIST(APPEND RSPAMD_REQUIRED_LIBRARIES rspamd-ced)

IF(ENABLE_CLANG_PLUGIN MATCHES "ON")
	ADD_SUBDIRECTORY(clang-plugin)
ENDIF()

ADD_SUBDIRECTORY(src)
ADD_SUBDIRECTORY(test)
ADD_SUBDIRECTORY(utils)

############################ TARGETS SECTION ###############################

CONFIGURE_FILE(config.h.in src/config.h)

##################### INSTALLATION ##########################################

# Binaries

# Configs
INSTALL(CODE "FILE(MAKE_DIRECTORY \$ENV{DESTDIR}${CONFDIR})")
INSTALL(CODE "FILE(MAKE_DIRECTORY \$ENV{DESTDIR}${SHAREDIR})")
INSTALL(CODE "FILE(MAKE_DIRECTORY \$ENV{DESTDIR}${LUALIBDIR})")
INSTALL(CODE "FILE(MAKE_DIRECTORY \$ENV{DESTDIR}${PLUGINSDIR})")
INSTALL(CODE "FILE(MAKE_DIRECTORY \$ENV{DESTDIR}${RULESDIR})")

# Install configs only if they are unchanged
LIST(LENGTH CONFFILES CONFLIST_COUNT)
MATH(EXPR CONFLIST_MAX ${CONFLIST_COUNT}-1)

FILE(GLOB_RECURSE CONF_FILES RELATIVE "${CMAKE_SOURCE_DIR}/conf" CONFIGURE_DEPENDS
	"${CMAKE_SOURCE_DIR}/conf/*.conf"
	"${CMAKE_SOURCE_DIR}/conf/*.inc" )
FOREACH(CONF_FILE ${CONF_FILES})
	GET_FILENAME_COMPONENT(_rp ${CONF_FILE} PATH)
	INSTALL(CODE "FILE(MAKE_DIRECTORY \$ENV{DESTDIR}${CONFDIR}/${_rp})")
	INSTALL(FILES "${CMAKE_CURRENT_SOURCE_DIR}/conf/${CONF_FILE}"
		DESTINATION ${CONFDIR}/${_rp})
ENDFOREACH(CONF_FILE)

# Lua plugins

FILE(GLOB LUA_PLUGINS RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}/src/plugins/lua" CONFIGURE_DEPENDS
	"${CMAKE_CURRENT_SOURCE_DIR}/src/plugins/lua/*.lua" )
FOREACH(LUA_PLUGIN ${LUA_PLUGINS})
	GET_FILENAME_COMPONENT(_rp ${LUA_PLUGIN} PATH)
	INSTALL(CODE "FILE(MAKE_DIRECTORY \$ENV{DESTDIR}${PLUGINSDIR}/${_rp})")
	INSTALL(FILES "src/plugins/lua/${LUA_PLUGIN}" DESTINATION ${PLUGINSDIR}/${_rp})
ENDFOREACH(LUA_PLUGIN)


# Install TLD list
INSTALL(FILES "contrib/publicsuffix/effective_tld_names.dat" DESTINATION
	"${SHAREDIR}")

# Install languages data
INSTALL(CODE "FILE(MAKE_DIRECTORY \$ENV{DESTDIR}${SHAREDIR}/languages)")
FILE(GLOB LANGUAGES CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/contrib/languages-data/*.json")
FOREACH(_LANG ${LANGUAGES})
	INSTALL(FILES "${_LANG}" DESTINATION ${SHAREDIR}/languages)
ENDFOREACH()
INSTALL(FILES "${CMAKE_CURRENT_SOURCE_DIR}/contrib/languages-data/stop_words" DESTINATION ${SHAREDIR}/languages)

# Lua config
FILE(GLOB_RECURSE LUA_CONFIGS RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}/rules" CONFIGURE_DEPENDS
	"${CMAKE_CURRENT_SOURCE_DIR}/rules/*.lua")
FOREACH(LUA_CONF ${LUA_CONFIGS})
	GET_FILENAME_COMPONENT(_rp ${LUA_CONF} PATH)
	INSTALL(CODE "FILE(MAKE_DIRECTORY \$ENV{DESTDIR}${RULESDIR}/${_rp})")
	INSTALL(FILES "rules/${LUA_CONF}" DESTINATION ${RULESDIR}/${_rp})
ENDFOREACH(LUA_CONF)

# Lua libs
FILE(GLOB_RECURSE LUA_LIBS RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}/lualib" CONFIGURE_DEPENDS
		"${CMAKE_CURRENT_SOURCE_DIR}/lualib/*.lua")
FOREACH(LUA_LIB ${LUA_LIBS})
	GET_FILENAME_COMPONENT(_rp ${LUA_LIB} PATH)
	INSTALL(CODE "FILE(MAKE_DIRECTORY \$ENV{DESTDIR}${LUALIBDIR}/${_rp})")
	INSTALL(FILES "lualib/${LUA_LIB}" DESTINATION ${LUALIBDIR}/${_rp})
ENDFOREACH(LUA_LIB)

# Install lua fun library
INSTALL(FILES "contrib/lua-fun/fun.lua" DESTINATION ${LUALIBDIR})
INSTALL(FILES "contrib/lua-argparse/argparse.lua" DESTINATION ${LUALIBDIR})
INSTALL(FILES "contrib/lua-tableshape/tableshape.lua" DESTINATION ${LUALIBDIR})
INSTALL(FILES "contrib/lua-lupa/lupa.lua" DESTINATION ${LUALIBDIR})
INSTALL(FILES "contrib/lua-lpeg/lpegre.lua" DESTINATION ${LUALIBDIR})

# systemd unit
IF(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND WANT_SYSTEMD_UNITS MATCHES "ON")
	INSTALL(FILES "rspamd.service" DESTINATION ${SYSTEMDDIR})
ENDIF(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND WANT_SYSTEMD_UNITS MATCHES "ON")

# Manual pages
INSTALL(FILES "doc/rspamd.8" DESTINATION ${MANDIR}/man8)
INSTALL(FILES "doc/rspamc.1" DESTINATION ${MANDIR}/man1)
INSTALL(FILES "doc/rspamadm.1" DESTINATION ${MANDIR}/man1)

# Utils
INSTALL(PROGRAMS "utils/rspamd_stats.pl" RENAME rspamd_stats DESTINATION bin)

# Install webui
IF(INSTALL_WEBUI MATCHES "ON")
	INSTALL(DIRECTORY "interface/" DESTINATION ${WWWDIR} PATTERN ".git" EXCLUDE)
ENDIF(INSTALL_WEBUI MATCHES "ON")


INSTALL(DIRECTORY "contrib/elastic/" DESTINATION "${SHAREDIR}/elastic" PATTERN ".git" EXCLUDE)

ADD_CUSTOM_TARGET(dist ${CMAKE_SOURCE_DIR}/dist.sh
	"${CMAKE_BINARY_DIR}/rspamd-${RSPAMD_VERSION}.tar.xz" "${TAR}"
	COMMENT "Create source distribution"
	WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})

IF(NOT DEBIAN_BUILD)
	ADD_CUSTOM_TARGET(check DEPENDS rspamd-test-cxx)
	ADD_CUSTOM_TARGET(run-test DEPENDS check COMMAND test/rspamd-test-cxx)
ENDIF(NOT DEBIAN_BUILD)


# PVS Studio
find_program(_PVS_STUDIO "pvs-studio-analyzer")

if(_PVS_STUDIO)
	include(PVS-Studio)
	pvs_studio_add_target(TARGET ${PROJECT_NAME}.analyze
			ANALYZE ${PROJECT_NAME} rspamd-server rspamadm rspamc
			OUTPUT FORMAT errorfile
			LOG target_${PROJECT_NAME}.err)
endif()
