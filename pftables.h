#ifndef __PFTABLES_H__

#define __PFTABLES_H__ 1

enum {  PFRB_TABLES = 1, PFRB_TSTATS, PFRB_ADDRS, PFRB_ASTATS, PFRB_IFACES, PFRB_TRANS, PFRB_MAX };
struct pfr_buffer {
  int   pfrb_type;  /* type of content, see enum above */
  int   pfrb_size;  /* number of objects in buffer */
  int   pfrb_msize;  /* maximum number of objects in buffer */
  void  *pfrb_caddr;  /* malloc'ated memory area */
};

size_t buf_esize[PFRB_MAX] = { 0,
  sizeof(struct pfr_table), sizeof(struct pfr_tstats),
  sizeof(struct pfr_addr), sizeof(struct pfr_astats),
  sizeof(struct pfi_kif), sizeof(struct pfioc_trans_e)
};

#define PFRB_FOREACH(var, buf)        \
  for ((var) = pfr_buf_next((buf), NULL);    \
      (var) != NULL;        \
      (var) = pfr_buf_next((buf), (var)))

int   pfr_get_tables(struct pfr_table *, struct pfr_table *, int *, int);
int   pfr_get_addrs(struct pfr_table *, struct pfr_addr *, int *, int);
int   pfr_buf_add(struct pfr_buffer *, const void *);
void  *pfr_buf_next(struct pfr_buffer *, const void *);
int   pfr_buf_grow(struct pfr_buffer *, int);
char  *pfr_strerror(int);

FILE  *pfctl_fopen(const char *, const char *);

static int count_table_entries(char *, int);
static void radix_perror(void);

#endif
