#ifndef SSLTEST_H
#define SSLTEST_H

#ifndef WIN32
#define INVALID_SOCKET -1
#define SOCKET int
#define PACKED __attribute__((packed))
#else
#include <pshpack1.h>
#define PACKED
#define ushort unsigned short
#define perror print_error
#endif

extern SOCKET ssl_connection(struct in_addr*, u_short, EVP_PKEY**);
extern int server_check(unsigned char *guess, unsigned int guess_len);

#endif /* SSLTEST_H */
