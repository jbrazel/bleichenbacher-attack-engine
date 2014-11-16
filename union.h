#ifndef _UNION_H
#define _UNION_H

typedef struct _set {
  BIGNUM *a;
  BIGNUM *b;
  struct _set *next;
} set;

extern void add_set(set**, BIGNUM*, BIGNUM*);
extern void free_set(set**);
extern int num_sets(set**);

#endif /* _UNION_H */
