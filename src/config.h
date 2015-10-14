/* src/config.h.  Generated from config.h.in by configure.  */
/* src/config.h.in.  Generated from configure.ac by autoheader.  */

/* Define this to enable the experimental draft edns cookies. */
/* #undef EDNS_COOKIES */

#define USE_WINSOCK 1
#define GETDNS_ON_WINDOWS 1

/* Whether getaddrinfo is available */
#define HAVE_GETADDRINFO 1
/*g
#define SCHED_DEBUG 1
#define SEC_DEBUG 1
#define STUB_DEBUG 1
*/
#define STUB_NATIVE_DNSSEC 1

#define HAVE_WINSOCK2_H 1
#define HAVE_WS2TCPIP_H 1

/* the version of the windows API enabled */
#undef WINVER
#undef _WIN32_WINNT
#define WINVER 0x0600 //g 0x0502
#define _WIN32_WINNT 0x0600 //0x0502
#ifdef HAVE_WINSOCK2_H
#include <winsock2.h>
#include<BaseTsd.h>
#endif

#ifdef HAVE_WS2TCPIP_H
#include <ws2tcpip.h>
#endif

#ifndef USE_WINSOCK
#define ARG_LL "%ll"
#else
#define ARG_LL "%I64"
#endif


	/* detect if we need to cast to unsigned int for FD_SET to avoid warnings */
#ifdef HAVE_WINSOCK2_H
#define FD_SET_T (u_int)
#else
#define FD_SET_T 
#endif

/* in_addr_t */
#define in_addr_t uint32_t

/* in_port_t */
#define in_port_t uint16_t

/* The edns cookie option code. */
#define EDNS_COOKIE_OPCODE 65001

/* How often the edns client cookie is refreshed. */
#define EDNS_COOKIE_ROLLOVER_TIME (24 * 60 * 60)

/* Define to 1 if you have the `arc4random' function. */
/* #undef HAVE_ARC4RANDOM */

/* Define to 1 if you have the `arc4random_uniform' function. */
/* #undef HAVE_ARC4RANDOM_UNIFORM */

/* Define to 1 if you have the <arpa/inet.h> header file. */
/* #undef HAVE_ARPA_INET_H */

/* Whether the C compiler accepts the "format" attribute */
#define HAVE_ATTR_FORMAT 1

/* Whether the C compiler accepts the "unused" attribute */
#define HAVE_ATTR_UNUSED 1

/* Define to 1 if you have the <bsd/string.h> header file. */
/* #undef HAVE_BSD_STRING_H */

/* Define to 1 if you have the declaration of `arc4random', and to 0 if you
   don't. */
#define HAVE_DECL_ARC4RANDOM 0

/* Define to 1 if you have the declaration of `arc4random_uniform', and to 0
   if you don't. */
#define HAVE_DECL_ARC4RANDOM_UNIFORM 0

/* Define to 1 if you have the declaration of `strlcpy', and to 0 if you
   don't. */
#define HAVE_DECL_STRLCPY 0

/* Define to 1 if you have the <dlfcn.h> header file. */
#define HAVE_DLFCN_H 1

/* Define to 1 if you have the <event2/event.h> header file. */
/* #undef HAVE_EVENT2_EVENT_H */

/* Define to 1 if you have the `event_base_free' function. */
/* #undef HAVE_EVENT_BASE_FREE */

/* Define to 1 if you have the `event_base_new' function. */
/* #undef HAVE_EVENT_BASE_NEW */

/* Define to 1 if you have the <event.h> header file. */
/* #undef HAVE_EVENT_H */

/* Define to 1 if you have the <ev.h> header file. */
/* #undef HAVE_EV_H */

/* Define to 1 if you have the `fcntl' function. */
/* #undef HAVE_FCNTL */

/* Define to 1 if you have the `getauxval' function. */
/* #undef HAVE_GETAUXVAL */

/* Define to 1 if you have the `getentropy' function. */
/* #undef HAVE_GETENTROPY */

/* If you have HMAC_CTX_init */
#define HAVE_HMAC_CTX_INIT 1

/* Define to 1 if you have the <inttypes.h> header file. */
#define HAVE_INTTYPES_H 1

/* if the function 'ioctlsocket' is available */
/* #undef HAVE_IOCTLSOCKET */

/* Define to 1 if you have the <libev/ev.h> header file. */
/* #undef HAVE_LIBEV_EV_H */

/* Define to 1 if you have the `idn' library (-lidn). */
/* #undef HAVE_LIBIDN */

/* Define to 1 if you have the `ldns' library (-lldns). */
/* #undef HAVE_LIBLDNS */

/* Define if you have libssl with tls 1.2 */
/* #undef HAVE_LIBTLS1_2 */

/* Define to 1 if you have the `unbound' library (-lunbound). */
/* #undef HAVE_LIBUNBOUND */

/* Define to 1 if you have the <memory.h> header file. */
#define HAVE_MEMORY_H 1

/* Define to 1 if you have the <netdb.h> header file. */
/* #undef HAVE_NETDB_H */

/* Define to 1 if you have the <netinet/in.h> header file. */
/* #undef HAVE_NETINET_IN_H */

/* Does libuv have the new uv_time_cb signature */
/* #undef HAVE_NEW_UV_TIMER_CB */

/* Define to 1 if you have the <openssl/err.h> header file. */
#define HAVE_OPENSSL_ERR_H 1

/* Define to 1 if you have the <openssl/rand.h> header file. */
#define HAVE_OPENSSL_RAND_H 1

/* Define to 1 if you have the <openssl/ssl.h> header file. */
#define HAVE_OPENSSL_SSL_H 1

/* Define to 1 if you have the `SHA512_Update' function. */
/* #undef HAVE_SHA512_UPDATE */

/* Define if you have the SSL libraries installed. */
#define HAVE_SSL /**/

/* Define to 1 if you have the <stdarg.h> header file. */
#define HAVE_STDARG_H 1

/* Define to 1 if you have the <stdint.h> header file. */
#define HAVE_STDINT_H 1

/* Define to 1 if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H 1

/* Define to 1 if you have the <strings.h> header file. */
#define HAVE_STRINGS_H 1

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* Define to 1 if you have the `strlcpy' function. */
/* #undef HAVE_STRLCPY */

/* Define to 1 if you have the <sys/sha2.h> header file. */
/* #undef HAVE_SYS_SHA2_H */

/* Define to 1 if you have the <sys/socket.h> header file. */
/* #undef HAVE_SYS_SOCKET_H */

/* Define to 1 if you have the <sys/stat.h> header file. */
#define HAVE_SYS_STAT_H 1

/* Define to 1 if you have the <sys/sysctl.h> header file. */
/* #undef HAVE_SYS_SYSCTL_H */

/* Define to 1 if you have the <sys/time.h> header file. */
#define HAVE_SYS_TIME_H 1

/* Define to 1 if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1

/* Define to 1 if you have the <time.h> header file. */
#define HAVE_TIME_H 1

/* Define to 1 if you have the <unistd.h> header file. */
#define HAVE_UNISTD_H 1

/* Define to 1 if you have the <uv.h> header file. */
/* #undef HAVE_UV_H */

/* When defined ldns_dnssec_zone contained the hashed_names member. */
/* #undef LDNS_DNSSEC_ZONE_HASHED_NAMES */

/* Define to the sub-directory where libtool stores uninstalled libraries. */
#define LT_OBJDIR ".libs/"

/* Define to the address where bug reports for this package should be sent. */
#define PACKAGE_BUGREPORT "stub-resolver@verisignlabs.com"

/* Define to the full name of this package. */
#define PACKAGE_NAME "getdns"

/* Define to the full name and version of this package. */
#define PACKAGE_STRING "getdns 0.2.0"

/* Define to the one symbol short name of this package. */
#define PACKAGE_TARNAME "getdns"

/* Define to the home page for this package. */
#define PACKAGE_URL "http://getdnsapi.net"

/* Define to the version of this package. */
#define PACKAGE_VERSION "0.2.0"

/* Define as the return type of signal handlers (`int' or `void'). */
#define RETSIGTYPE void

/* Define to 1 if you have the ANSI C header files. */
#define STDC_HEADERS 1

/* Define this to enable the very experimental and broken native stub DNSSEC
   support. */
/* #undef STUB_NATIVE_DNSSEC */

/* System configuration dir */
#define SYSCONFDIR sysconfdir

/* Default trust anchor file */
#define TRUST_ANCHOR_FILE "/etc/unbound/getdns-root.key"

/* Needed for sync stub resolver functions */
#define USE_MINI_EVENT 1

/* Define this to enable TCP fast open. */
/* #undef USE_TCP_FASTOPEN */

/* Define for Solaris 2.5.1 so the uint32_t typedef from <sys/synch.h>,
   <pthread.h>, or <semaphore.h> is not used. If the typedef were allowed, the
   #define below would cause a syntax error. */
/* #undef _UINT32_T */

/* Define for Solaris 2.5.1 so the uint64_t typedef from <sys/synch.h>,
   <pthread.h>, or <semaphore.h> is not used. If the typedef were allowed, the
   #define below would cause a syntax error. */
/* #undef _UINT64_T */

/* Define for Solaris 2.5.1 so the uint8_t typedef from <sys/synch.h>,
   <pthread.h>, or <semaphore.h> is not used. If the typedef were allowed, the
   #define below would cause a syntax error. */
/* #undef _UINT8_T */

/* Define to `unsigned int' if <sys/types.h> does not define. */
/* #undef size_t */

/* Define to the type of an unsigned integer type of width exactly 16 bits if
   such a type exists and the standard includes do not define it. */
/* #undef uint16_t */

/* Define to the type of an unsigned integer type of width exactly 32 bits if
   such a type exists and the standard includes do not define it. */
/* #undef uint32_t */

/* Define to the type of an unsigned integer type of width exactly 64 bits if
   such a type exists and the standard includes do not define it. */
/* #undef uint64_t */

/* Define to the type of an unsigned integer type of width exactly 8 bits if
   such a type exists and the standard includes do not define it. */
/* #undef uint8_t */


#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#if STDC_HEADERS
#include <stdlib.h>
#include <stddef.h>
#endif

#if !defined(HAVE_STRLCPY) || !HAVE_DECL_STRLCPY
size_t strlcpy(char *dst, const char *src, size_t siz);
#else
#define __BSD_VISIBLE 1
#endif
#if !defined(HAVE_ARC4RANDOM) || !HAVE_DECL_ARC4RANDOM
uint32_t arc4random(void);
#endif
#if !defined(HAVE_ARC4RANDOM_UNIFORM) || !HAVE_DECL_ARC4RANDOM_UNIFORM 
uint32_t arc4random_uniform(uint32_t upper_bound);
#endif
#ifndef HAVE_ARC4RANDOM
void explicit_bzero(void* buf, size_t len);
int getentropy(void* buf, size_t len);
void arc4random_buf(void* buf, size_t n);
void _ARC4_LOCK(void);
void _ARC4_UNLOCK(void);
#endif
#ifdef COMPAT_SHA512
#ifndef SHA512_DIGEST_LENGTH
#define SHA512_BLOCK_LENGTH             128
#define SHA512_DIGEST_LENGTH            64
#define SHA512_DIGEST_STRING_LENGTH     (SHA512_DIGEST_LENGTH * 2 + 1)
typedef struct _SHA512_CTX {
        uint64_t        state[8];
        uint64_t        bitcount[2];
        uint8_t buffer[SHA512_BLOCK_LENGTH];
} SHA512_CTX;
#endif /* SHA512_DIGEST_LENGTH */
void SHA512_Init(SHA512_CTX*);
void SHA512_Update(SHA512_CTX*, void*, size_t);
void SHA512_Final(uint8_t[SHA512_DIGEST_LENGTH], SHA512_CTX*);
unsigned char *SHA512(void* data, unsigned int data_len, unsigned char *digest);
#endif /* COMPAT_SHA512 */

#ifdef __cplusplus
}
#endif

/** Use on-board gldns */
#define USE_GLDNS 1
#ifdef HAVE_SSL
#  define GLDNS_BUILD_CONFIG_HAVE_SSL 1
#endif

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

#ifdef HAVE_STDARG_H
#include <stdarg.h>
#endif

#include <errno.h>

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#ifdef HAVE_OPENSSL_SSL_H
#include <openssl/ssl.h>
#endif

#ifdef HAVE_ATTR_FORMAT
#  define ATTR_FORMAT(archetype, string_index, first_to_check) \
    __attribute__ ((format (archetype, string_index, first_to_check)))
#else /* !HAVE_ATTR_FORMAT */
#  define ATTR_FORMAT(archetype, string_index, first_to_check) /* empty */
#endif /* !HAVE_ATTR_FORMAT */

#if defined(DOXYGEN)
#  define ATTR_UNUSED(x)  x
#elif defined(__cplusplus)
#  define ATTR_UNUSED(x)
#elif defined(HAVE_ATTR_UNUSED)
#  define ATTR_UNUSED(x)  x __attribute__((unused))
#else /* !HAVE_ATTR_UNUSED */
#  define ATTR_UNUSED(x)  x
#endif /* !HAVE_ATTR_UNUSED */

/* detect if we need to cast to unsigned int for FD_SET to avoid warnings */
#ifdef HAVE_WINSOCK2_H
#define FD_SET_T (u_int)
#else
#define FD_SET_T 
#endif

#ifdef TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# ifdef HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

#ifdef HAVE_BSD_STRING_H
#include <bsd/string.h>
#endif

