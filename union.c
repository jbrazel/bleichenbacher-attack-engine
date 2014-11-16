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
#include <stdlib.h>
#include <openssl/bn.h>
#include "union.h"

void 
add_set(set **list, BIGNUM *lower, BIGNUM *upper)
{
  set *s = (set*)malloc(sizeof(*s));

  if (s == NULL) {
    perror("add_set: malloc(set)");
    exit(1);
  }

  if ((s->a = BN_dup(lower)) == NULL ||
      (s->b = BN_dup(upper)) == NULL)
    {
      fputs("add_set: BN_dup(a,b) failed\n", stderr);
      exit(1);
    }

  /* ordering of sets in M[i] is not important */
  s->next = *list;
  *list = s;
}

void 
free_set(set **m)
{
  while(*m != NULL) 
    {
      set *s = *m;
      *m = (*m)->next;
      BN_free(s->a);
      BN_free(s->b);
      free(s);
    }
}

int 
num_sets(set **m)
{
  set *s = *m;
  int n = 0;
  
  if (s)
    do n++; while(((s = s->next) != NULL) && (s != *m));

  return n;
}

/* Eof */
