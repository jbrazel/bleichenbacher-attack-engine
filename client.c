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
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include "union.h"
#include "ssltest.h"

extern int keysize;
extern EVP_PKEY *pubkey;
extern unsigned char *encrypted_secret;
extern unsigned short port;
extern struct in_addr addr;

static set *Mi = NULL, *Mi_1 = NULL;
static BIGNUM *B, *res, *c, *lower, *upper, *algmin, *algmax;
static BN_CTX *scratch = NULL;
static unsigned char *guess_buffer;
static int i;
static int total_queries = 0;

static BIGNUM *client_step_2a(void);
static BIGNUM *client_step_2b(BIGNUM*);
static BIGNUM *client_step_2b_parallel(BIGNUM*,set*);
static BIGNUM *client_step_2c(BIGNUM*);
static void client_step_3(BIGNUM*);
static void client_step_4(void);

void
client_setup(char *premaster_secret)
{
  BIGNUM *B_exponent;
  SOCKET sock;
  int fd;

  if ((guess_buffer = (unsigned char*)malloc(keysize)) == NULL) 
    {
      perror("malloc(guess_buffer)");
      exit(1);
    }

  /* Make a single connection to get the public key. */
  puts("Connecting...");

  sock = ssl_connection(&addr, port, &pubkey);

  if (sock == INVALID_SOCKET)
  {
    fputs("Remote server is down\n", stderr);
    exit(-1);
  }

#ifdef WIN32
  closesocket(sock);
#else
  close(sock);
#endif

  puts("RSA public key:");
  RSA_print_fp(stdout, pubkey->pkey.rsa, 0);
  puts("");

  keysize = BN_num_bytes(pubkey->pkey.rsa->n);

  if ((encrypted_secret = (char*)malloc(keysize + 1)) == NULL)
    {
      perror("malloc(premaster_secret)");
      exit(1);
    }

  if ((fd = open(premaster_secret, O_RDONLY)) < 0) {
    perror(premaster_secret);
    exit(1);
  }

  if (read(fd, encrypted_secret, keysize+1) != keysize) {
    fputs("Premaster secret size mismatch!\n", stderr);
    exit(1);
  }

  close(fd);

  /* Calculate bound unit: B = 2^(8*(k-2)), where
   * k = size of RSA modulus in bytes.
   */
  
  if ((res = BN_new()) == NULL ||
      (B = BN_new()) == NULL ||
      (lower = BN_new()) == NULL ||
      (upper = BN_new()) == NULL ||
      (scratch = BN_CTX_new()) == NULL ||
      (B_exponent = BN_new()) == NULL ||
      (algmin = BN_new()) == NULL ||
      (algmax = BN_new()) == NULL)
    {
      fprintf(stderr, "client_setup() failed: ");
      ERR_print_errors_fp(stderr);
      fputs("\n", stderr);
      exit(1);
    }

  if ((!BN_set_word(B_exponent, 8 * (keysize-2))) ||
      (!BN_set_word(res, 2)) ||
      (!BN_exp(B, res, B_exponent, scratch)))
    {
      fprintf(stderr, "Creation of initial B failed: ");
      ERR_print_errors_fp(stderr);
      fputs("\n", stderr);
      exit(1);
    }

  puts("B:");
  BN_print_fp(stdout, B);
  puts("");

  BN_free(B_exponent);

  {
    BIGNUM twofivesix, exp_val, tmp, tmp2;
    
    BN_init(&twofivesix);
    BN_init(&exp_val);
    BN_init(&tmp);
    BN_init(&tmp2);

    if ((!BN_set_word(&twofivesix, 256)) ||
	(!BN_set_word(&exp_val, keysize - 51)) ||
	(!BN_exp(&tmp, &twofivesix, &exp_val, scratch)) ||
	(!BN_sub_word(&tmp, 1)) ||
	(!BN_set_word(&exp_val, 49)) ||
	(!BN_exp(res, &twofivesix, &exp_val, scratch)) ||
	(!BN_mul(&tmp2, &tmp, res, scratch)))
      {
	fputs("client_setup: failed to calculate algorithm min,\n", stderr);
	exit(1);
      }

    BN_div_word(&tmp2, 255);

    if ((!BN_copy(&tmp, B)) ||
	(!BN_mul_word(&tmp, 2)) ||
	(!BN_add(algmin, &tmp, &tmp2)))
      {
	fputs("client_setup: failed to calculate algorithm min,\n", stderr);
	exit(1);
      }
    
    puts("E':");
    BN_print_fp(stdout, algmin);
    puts("");

    if ((!BN_set_word(&exp_val, 48)) ||
	(!BN_exp(res, &twofivesix, &exp_val, scratch)) ||
	(!BN_mul_word(res, 255)) ||
	(!BN_copy(&tmp, B)) ||
	(!BN_mul_word(&tmp, 3)) ||
	(!BN_sub(algmax, &tmp, res)) ||
	(!BN_sub_word(algmax, 1))) 
      {
	fputs("client_setup: failed to calculate algorithm min,\n", stderr);
	exit(1);
      }
    
    puts("F':");
    BN_print_fp(stdout, algmax);
    puts("");
	
    BN_free(&tmp);
    BN_free(&tmp2);
    BN_free(&exp_val);
    BN_free(&twofivesix);
  }

  if ((c = BN_bin2bn(encrypted_secret, keysize, NULL)) == NULL)
    {
      fprintf(stderr, "Conversion of encrypted secret to BIGNUM failed: ");
      ERR_print_errors_fp(stderr);
      fputs("\n", stderr);
      exit(1);
    }

  puts("C:");
  BN_print_fp(stdout, c);
  puts("");

  i = 0;
}

void
client_step_1(void)
{
  BIGNUM *Si_1 = NULL;

  add_set(&Mi_1, algmin, algmax);
  i = 1;

  while(1)
    {
      BIGNUM *tmp;

      if (i == 1)
	Si_1 = client_step_2a();
      else 
	{
	  if (num_sets(&Mi_1) > 1) 
	    {
	      //tmp = client_step_2b(Si_1);
	      tmp = client_step_2b_parallel(Si_1,Mi_1);
	    }
	  else
	    tmp = client_step_2c(Si_1);
	  
	  BN_free(Si_1);
	  Si_1 = tmp;
	}

      /* M[i-1] = M[i] */
      
      free_set(&Mi_1);
      Mi_1 = Mi;
      Mi = NULL;
    }
}

static int
step_2_guess(BIGNUM *s)
{
  BIGNUM blind;
  int debug = 0, rv, pad_length, len;

  BN_init(&blind);

  if (!BN_mod_exp(res, s, pubkey->pkey.rsa->e, pubkey->pkey.rsa->n, scratch))
    {
      fputs("Modular exponentiation of blind factor s failed: ", stderr);
      ERR_print_errors_fp(stderr);
      fputs("\n", stderr);
      exit(1);
    }

  if (!BN_mod_mul(&blind, res, c, pubkey->pkey.rsa->n, scratch))
    {
      fputs("Modular multiplication of blind factor with ciphertext failed: ", stderr);
      ERR_print_errors_fp(stderr);
      fputs("\n", stderr);
      exit(1);
    }
  
  if (debug)
    {
      printf("blind: "); 
      BN_print_fp(stdout, &blind); 
      puts("\n");
    }
  
  if ((len = BN_num_bytes(&blind)) > keysize)
    {
      fprintf(stderr, "HELP! Size of encoded guess %u > %u bytes\n",
	      len, keysize);
      exit(1);
    }
  
  /* Ensure size is padded to that of an RSA modulus */
  
  memset(guess_buffer, 0, keysize);
  pad_length = keysize - len;
  
  if (!BN_bn2bin(&blind, guess_buffer + pad_length))
    {
      fputs("Huh? Serializing guess failed? ", stderr);
      ERR_print_errors_fp(stderr);
      fputs("\n", stderr);
      exit(1);
    }

  do {
    rv = server_check(guess_buffer, keysize);
    if (rv < 0) {
      /* delay */
      fputs("Error talking to server, retrying...\n", stderr);
      sleep(1);
    }
  } while(rv < 0);

  total_queries++;
  BN_free(&blind);
  return rv;
}

static BIGNUM*
step_2_loop(BIGNUM *s, BIGNUM *upper_limit)
{
  int n_attempts = 0;
  int debug = 0;

  while((upper_limit == NULL) || (BN_cmp(s, upper_limit) <= 0))
    {
      if (debug) printf("Guess %u: \n",n_attempts);

      if (step_2_guess(s))
	{
	  printf("Got it in %u attempts (%u total so far): \n", n_attempts,
		 total_queries);
	  BN_print_fp(stdout, s);
	  puts("\n");
	  break;
	}
      
      if (!BN_add_word(s, 1)) 
	{
	  fputs("s++ failed? ", stderr);
	  ERR_print_errors_fp(stderr);
	  fputs("\n", stderr);
	  exit(1);
	}
      
      if ((++n_attempts % 1000) == 0)
	{
	  printf("\r%u", n_attempts);
	  fflush(stdout);
	}
    }

  if (debug) puts("");
  return s;
}

static BIGNUM*
client_step_2a(void)
{
  BIGNUM *s = BN_new();

  puts("step 2a:");

  if (s == NULL) 
    {
      fprintf(stderr, "Creation of tmp variable s failed: ");
      ERR_print_errors_fp(stderr);
      fputs("\n", stderr);
      exit(1);      
    }

  if ((BN_copy(res, algmax) == NULL) ||
      (!BN_add_word(res, 1)) ||
      (!BN_div(s, NULL, pubkey->pkey.rsa->n, res, scratch)))
    {
      fprintf(stderr, "Calculation of initial S failed: ");
      ERR_print_errors_fp(stderr);
      fputs("\n", stderr);
      exit(1);      
    }

  printf("S = n/(F'+1) == ");
  BN_print_fp(stdout, s);
  puts("\n");

  s = step_2_loop(s, NULL);
  client_step_3(s);

  return s;
}

static BIGNUM*
client_step_2b(BIGNUM *Si_1)
{
  BIGNUM *s = BN_dup(Si_1);

  puts("step 2b:");

  if (s == NULL) 
    {
      fputs("step_2b(): copy of S[i-1] failed\n", stderr);
      exit(1);
    }
  
  if (!BN_add_word(s, 1)) 
    {
      fputs("step_2b(): increment of Si failed\n", stderr);
      exit(1);
    }

  s = step_2_loop(s, NULL);  
  client_step_3(s);

  return s;
}

static void
client_step_2_calculate_r(BIGNUM *Si_1, BIGNUM *b, BIGNUM *r)
{
  BIGNUM tmp;

  BN_init(&tmp);

  if ((!BN_copy(r, b)) ||
      (!BN_mul(&tmp, r, Si_1, scratch)) ||
      (!BN_sub(res, &tmp, algmin)) ||
      (!BN_mul_word(res, 2)) ||
      (!BN_div(r, &tmp, res, pubkey->pkey.rsa->n, scratch)))
    {
      fputs("client_step_2c: calculation of r failed\n", stderr);
      exit(1);
    }
  
  if (!BN_is_zero(&tmp))
    if (!BN_add_word(r, 1)) {
      fputs("Client_step_2c: round-up of r failed\n", stderr);
      exit(1);
    }  

  BN_free(&tmp);
}

static void
client_step_2_calculate_s_limits(set *m, BIGNUM *r, BIGNUM *lower, 
				 BIGNUM *upper)
{
  BIGNUM tmp;

  BN_init(&tmp);
  BN_init(lower);
  BN_init(upper);
  
  if ((!BN_mul(lower, r, pubkey->pkey.rsa->n, scratch)) ||
      (!BN_add(res, algmin, lower)) ||
      (!BN_div(lower, &tmp, res, m->b, scratch)))
    {
      fputs("client_step_2: calculation of s'lower failed\n", stderr);
      exit(1);
    }

  if (!BN_is_zero(&tmp)) 
    if (!BN_add_word(lower, 1)) {
      fputs("client_step_2: round up of s'lower failed\n", stderr);
      exit(1);
    }

  //printf("\tstep 2: s'lower: "); BN_print_fp(stdout, lower); puts("");
  
  if ((!BN_mul(upper, r, pubkey->pkey.rsa->n, scratch)) ||
      (!BN_add(res, algmax, upper)) ||
      (!BN_div(upper, &tmp, res, m->a, scratch)))
    {
      fputs("client_step_2: calculation of s'upper failed\n", stderr);
      exit(1);
    }

 #if 0 
  if (!BN_is_zero(&tmp)) 
    if (!BN_add_word(upper, 1)) {
      fputs("client_step_2: round up of s'upper failed\n", stderr);
      exit(1);
    }
 #endif 

  //printf("\tstep 2: s'upper: "); BN_print_fp(stdout, upper); puts("\n");

  BN_free(&tmp);
}

static BIGNUM*
client_step_2b_parallel(BIGNUM *Si_1, set *m)
{
  /* Implement client_step_2c() for an arbitrary number of sets,
   * and then cycle through each in turn, trying one value for s
   * from each.
   */

  struct thread_state {
    BIGNUM r;
    BIGNUM s;
    BIGNUM s_lower, s_upper;
    set *m;
  } *thread_list;
  int n_threads, n, n_attempts = 0;
  set *m_ptr = m;
  BIGNUM *s;
  
  n_threads = num_sets(&m);
  
  if ((thread_list = (struct thread_state*)malloc(n_threads * sizeof(struct thread_state))) == NULL)
    {
      perror("client_step_2b_parallel: malloc(thread list) failed");
      exit(1);
    }

  for(n = 0, m_ptr = m; m_ptr != NULL; n++, m_ptr = m_ptr->next)
    {
      BN_init(&thread_list[n].r);
      BN_init(&thread_list[n].s);
      BN_init(&thread_list[n].s_lower);
      BN_init(&thread_list[n].s_upper);

      thread_list[n].m = m_ptr;

      client_step_2_calculate_r(Si_1, m_ptr->b, &thread_list[n].r);
      client_step_2_calculate_s_limits(m_ptr, &thread_list[n].r, 
				       &thread_list[n].s_lower, 
				       &thread_list[n].s_upper);
      
      if (BN_copy(&thread_list[n].s, &thread_list[n].s_lower) == NULL)
	{
	  fputs("client_step_2b_parallel: init of s failed\n", stderr);
	  exit(1);
	}
    }
  
  for(n = 0;;)
    {
      if (BN_cmp(&thread_list[n].s, &thread_list[n].s_upper) > 0) 
	{
	  if (!BN_add_word(&thread_list[n].r, 1)) {
	    fputs("client_step_2c_parallel: Increment of r failed\n", stderr);
	    exit(1);
	  }
	  client_step_2_calculate_s_limits(thread_list[n].m, 
					   &thread_list[n].r, 
					   &thread_list[n].s_lower, 
					   &thread_list[n].s_upper);
	  
	  if (!BN_copy(&thread_list[n].s, &thread_list[n].s_lower))
	    {
	      fputs("client_step_2b_parallel: init of s failed\n", stderr);
	      exit(1);
	    }
	}
      
      if (step_2_guess(&thread_list[n].s))
	{
	  if ((s = BN_dup(&thread_list[n].s)) == NULL)
	    {
	      fputs("client_step_2b_parallel(): dup(successful s) failed\n",
		    stderr);
	      exit(1);
	    }

	  printf("Got it in %u attempts (%u total so far): \n", n_attempts,
		 total_queries);
	  BN_print_fp(stdout, s);
	  puts("\n");
	  break;
	}

      n_attempts++;

      if (!BN_add_word(&thread_list[n].s, 1)) 
	{
	  fputs("s++ failed? ", stderr);
	  ERR_print_errors_fp(stderr);
	  fputs("\n", stderr);
	  exit(1);
	}
      
      if ((++n_attempts % 1000) == 0)
	{
	  printf("\r%u", n_attempts);
	  fflush(stdout);
	}
  
      if (++n == n_threads)
	n = 0;
    }

  for(n=0;n<n_threads;n++)
    {
      BN_free(&thread_list[n].r);
      BN_free(&thread_list[n].s);
      BN_free(&thread_list[n].s_lower);
      BN_free(&thread_list[n].s_upper);
    }

  free(thread_list);

  client_step_3(s);
  return s;
}

static BIGNUM*
client_step_2c(BIGNUM *Si_1)
{
  BIGNUM tmp, r, *s;

  BN_init(&r);
  BN_init(&tmp);

  client_step_2_calculate_r(Si_1, Mi_1->b, &r);
  printf("step 2c: r >= "); BN_print_fp(stdout, &r); puts("\n");

  while(1)
    {
      BIGNUM lower, upper;

      printf("\tstep 2c: r = "); BN_print_fp(stdout, &r); puts("\n");

      client_step_2_calculate_s_limits(Mi_1, &r, &lower, &upper);

      if ((s = BN_dup(&lower)) == NULL) {
	fputs("client_step-2c: init of s failed\n", stderr);
	exit(1);
      }

      s = step_2_loop(s, &upper);

      if (BN_cmp(s, &upper) <= 0)
	break;
      
      if (!BN_add_word(&r, 1)) {
	fputs("step_2c: Increment of r failed\n", stderr);
	exit(1);
      }
    }

  client_step_3(s);

  BN_free(&r);
  BN_free(&tmp);
  return s;
}

static void
calculate_set_M(BIGNUM *r, BIGNUM *Si, set *s)
{
  BIGNUM lower_bound, upper_bound, tmp, remainder;

  BN_init(&tmp);
  BN_init(&remainder);
  BN_init(&lower_bound);
  
  if ((!BN_mul(&lower_bound, r, pubkey->pkey.rsa->n, scratch)) ||
      (!BN_add(res, algmin, &lower_bound)) ||
      (!BN_div(&lower_bound, &remainder, res, Si, scratch)))
    {
      fprintf(stderr, "calculate_set_M(): lower bound calculation failed\n");
      exit(1);
    }
  
  if ((!BN_is_zero(&remainder)) && (!BN_add_word(&lower_bound, 1))) 
    {
      fprintf(stderr, "calculate_set_M(): round up of lower bound faild\n");
      exit(1);
    }

  if (BN_cmp(s->a, &lower_bound) > 0)
    if (BN_copy(&lower_bound, s->a) == NULL)
      {
	fputs("calculate_set_M(): copy lower_bound <- a failed\n", stderr);
	exit(1);
      }

  BN_init(&upper_bound);

  if ((!BN_mul(&upper_bound, r, pubkey->pkey.rsa->n, scratch)) ||
      (!BN_add(res, algmax, &upper_bound)) ||
      (!BN_div(&upper_bound, NULL, res, Si, scratch)))
    {
      fprintf(stderr, "calculate_set_M(): lower bound calculation failed\n");
      exit(1);
    }  
  
  /* RHS is rounded down */

  if (BN_cmp(s->b, &upper_bound) < 0)
    if (BN_copy(&upper_bound, s->b) == NULL)
      {
	fputs("calculate_set_M(): copy upper_bound <- b failed\n", stderr);
	exit(1);
      }    

  printf("lower bound: "); BN_print_fp(stdout, &lower_bound); puts("");
  printf("upper bound: "); BN_print_fp(stdout, &upper_bound); puts("\n");

  if (BN_cmp(&lower_bound, &upper_bound) > 0)
    {
      fputs("HELP! lower bound > upper bound\n", stderr);
      exit(1);
    }

  add_set(&Mi, &lower_bound, &upper_bound);

  BN_free(&tmp);
  BN_free(&remainder);
  BN_free(&lower_bound);
  BN_free(&upper_bound);
}

static void
client_step_3(BIGNUM *Si)
{
  BIGNUM r, tmp, remainder;
  set *s;

  BN_init(&r);
  BN_init(&tmp);
  BN_init(&remainder);

  puts("step 3:");

  for(s = Mi_1; s != NULL; s = s->next)
    {
      printf("a "); BN_print_fp(stdout, s->a); puts("");
      printf("b "); BN_print_fp(stdout, s->b); puts("\n");

      if ((!BN_mul(&tmp, s->a, Si, scratch)) || 
	  (!BN_sub(res, &tmp, algmax)) ||
	  (!BN_div(lower, &remainder, res, pubkey->pkey.rsa->n, scratch)))
	{
	  fputs("client_step_3: lower bound of r failed\n", stderr);
	  exit(1);
	}
      
      /* Round up */
      
      if (!BN_is_zero(&remainder))
	if (!BN_add_word(lower, 1)) {
	  fputs("client_step_3: round-up of r failed\n", stderr);
	  exit(1);
	}

      printf("\tstep3 : r'lower =  "); BN_print_fp(stdout, lower); puts("\n");
      
      if ((!BN_mul(&tmp, s->b, Si, scratch)) ||
	  (!BN_sub(res, &tmp, algmin)) ||
	  (!BN_div(upper, NULL, res, pubkey->pkey.rsa->n, scratch)))
	{
	  fputs("client_step_3: upper bound of r failed\n", stderr);
	  exit(1);
	}      

      printf("\tstep 3: r'upper = "); BN_print_fp(stdout, upper); puts("\n");

      if (BN_copy(&r, lower) == NULL)
	{
	  fputs("client_step_3: BN_copy failed\n", stderr);
	  exit(1);
	}

      while(BN_cmp(&r, upper) <= 0)
	{
	  calculate_set_M(&r, Si, s);
	  if (!BN_add_word(&r, 1)) {
	    fputs("step_3(): r++ failed\n", stderr);
	    exit(1);
	  }
	}
    }

  printf("step 3: M[%i] has %i sets\n", i, num_sets(&Mi));

  if (num_sets(&Mi) == 0)
  {
    fputs("AIEEEEEEEEEEEEEE! M[i] has no sets!\n", stderr);
    exit(-1);
  }

  client_step_4();

  BN_clear(&r);
  BN_clear(&tmp);
  BN_clear(&remainder);
}

static void
client_step_4(void)
{
  if ((num_sets(&Mi) == 1) && (BN_cmp(Mi->a, Mi->b) == 0))
    {
      printf("Successful A: "); BN_print_fp(stdout, Mi->a); puts("");
      printf("Total of %u queries to the oracle.\n", total_queries);
      exit(0);
    }
  else
    {
      i++;
    }
}
