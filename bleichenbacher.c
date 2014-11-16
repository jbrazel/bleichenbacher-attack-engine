/**
 * Copyright (c) 2014, johnbrazel@gmail.com
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>

extern int debug, connect_timeout;

unsigned char *encrypted_secret;
EVP_PKEY *pubkey = NULL;
int keysize;

u_short port;
struct in_addr addr;

extern void client_setup(char*);
extern void client_step_1(void);

static void
usage(const char *argv0)
{
  fprintf(stderr, "Usage:\n\t%s [-d] [-t timeout] [-m premaster] server [port]\n", argv0);
  exit(1);
}

int
main(int argc, char **argv)
{
  char *premaster = NULL;

#ifdef WIN32
  {
    WSADATA wd;
    if (WSAStartup(MAKEWORD(2,0), &wd))
      perror("WSAStartup()");
  }
#endif

  ERR_load_RSA_strings();
  OpenSSL_add_all_ciphers();
  OpenSSL_add_all_digests();
  
  while(argc > 1 && *argv[1] == '-')
    {
      switch(argv[1][1])
	{
	case 'd':
	  debug = 1;
	  break;
	case 'm':
	  if (--argc < 2) 
	    usage(argv[0]);
	  argv++;
	  premaster = argv[1];
	  break;
	case 't':
	  if (--argc < 2) 
	    usage(argv[0]);
	  argv++;
	  connect_timeout = atoi(argv[1]);
	  break;	  
	}
      argc--;
      argv++;
    }
  
  if (argc < 2)
    usage(argv[0]);

#ifdef WIN32
  if ((addr.s_addr = inet_addr(argv[1])) == INADDR_NONE)
#else  
  if (!inet_aton(argv[1], &addr))
#endif
    {
      /* Hostname */
      struct hostent *h;
      
      if ((h = gethostbyname(argv[1])) == NULL)
	{
	  fprintf(stderr, "Bad hostname/IP '%s'\n", argv[1]);
	  exit(1);
	}
      
      memcpy(&addr.s_addr, h->h_addr_list[0], h->h_length);
    }
  
  if (argc > 2)
    port = htons((u_short)atoi(argv[2]));
  else
    port = htons(443);
  
  if (port == 0) 
    {
      fprintf(stderr, "Illegal port number 0\n");
      exit(1);
    }
  
  if (debug) 
    printf("Connecting to %s:%u\n", inet_ntoa(addr), ntohs(port));
  
  client_setup(premaster);
  client_step_1();

  exit(0);
}
 
