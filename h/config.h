#ifndef _TXMPP_CONFIG_H_
#define _TXMPP_CONFIG_H_

#define LINUX
#define FEATURE_ENABLE_SSL
#define HAVE_OPENSSL_SSL_H
#define POSIX
#define _POSIX_THREADS
#define SSL_USE_OPENSSL
#define USE_SSLSTREAM

/* IP_MTU_DISCOVER values */
#define IP_PMTUDISC_DONT                0       /* Never send DF frames */
#define IP_PMTUDISC_WANT                1       /* Use per route hints  */
#define IP_PMTUDISC_DO                  2       /* Always DF            */
#define IP_PMTUDISC_PROBE               3       /* Ignore dst pmtu      */

#define IP_TOS          1
#define IP_TTL          2
#define IP_HDRINCL      3
#define IP_OPTIONS      4
#define IP_ROUTER_ALERT 5
#define IP_RECVOPTS     6
#define IP_RETOPTS      7
#define IP_PKTINFO      8
#define IP_PKTOPTIONS   9
#define IP_MTU_DISCOVER 10
#define IP_RECVERR      11
#define IP_RECVTTL      12
#define IP_RECVTOS      13
#define IP_MTU          14
#define IP_FREEBIND     15
#define IP_IPSEC_POLICY 16
#define IP_XFRM_POLICY  17
#define IP_PASSSEC      18
#define IP_TRANSPARENT  19


#endif  // _TXMPP_CONFIG_H_
