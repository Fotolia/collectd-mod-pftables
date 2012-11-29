 /*
  * Code mostly taken from freebsd /usr/src/contrib/pf/pfctl/
  *
  * PF tables plugin
  * by Nicolas Szalay <nico _at_ rottenbytes _dot_ info>
  */


#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <net/if.h>
#include <net/pfvar.h>
#include <arpa/inet.h>

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>

#include "collectd.h"
#include "common.h"
#include "plugin.h"
#include "configfile.h"
#include "pftables.h"

#define PF_OPT_NOACTION          0x0008
#define PF_OPT_DUMMYACTION       0x0100

#define RVTEST(fct) do {        \
    if ((!(opts & PF_OPT_NOACTION) ||  \
        (opts & PF_OPT_DUMMYACTION)) &&  \
        (fct)) {        \
      radix_perror();      \
    }          \
  } while (0)

FILE *pfctl_fopen(const char *name, const char *mode)
{
  struct stat st;
  FILE *fp;

  fp = fopen(name, mode);
  if (fp == NULL)
    return (NULL);
  if (fstat(fileno(fp), &st)) {
    fclose(fp);
    return (NULL);
  }
  if (S_ISDIR(st.st_mode)) {
    fclose(fp);
    errno = EISDIR;
    return (NULL);
  }
  return (fp);
}

int pfr_get_tables(struct pfr_table *filter, struct pfr_table *tbl,
                   int *size, int flags)
{
  struct pfioc_table io;
  int dev;

  if (size == NULL || *size < 0 || (*size && tbl == NULL)) {
    errno = EINVAL;
    return (-1);
  }
  bzero(&io, sizeof io);
  io.pfrio_flags = flags;
  if (filter != NULL)
    io.pfrio_table = *filter;
  io.pfrio_buffer = tbl;
  io.pfrio_esize = sizeof(*tbl);
  io.pfrio_size = *size;
  dev = open("/dev/pf", 0);
  if (ioctl(dev, DIOCRGETTABLES, &io)) {
    close(dev);
    return (-1);
  }
  *size = io.pfrio_size;
  close(dev);
  return (0);
}

int pfr_buf_grow(struct pfr_buffer *b, int minsize)
{
  caddr_t p;
  size_t bs;

  if (b == NULL || b->pfrb_type <= 0 || b->pfrb_type >= PFRB_MAX) {
    errno = EINVAL;
    return (-1);
  }
  if (minsize != 0 && minsize <= b->pfrb_msize)
    return (0);
  bs = buf_esize[b->pfrb_type];
  if (!b->pfrb_msize) {
    if (minsize < 64)
      minsize = 64;
    b->pfrb_caddr = calloc(bs, minsize);
    if (b->pfrb_caddr == NULL)
      return (-1);
    b->pfrb_msize = minsize;
  } else {
    if (minsize == 0)
      minsize = b->pfrb_msize * 2;
    if (minsize < 0 || minsize >= SIZE_T_MAX / bs) {
      /* msize overflow */
      errno = ENOMEM;
      return (-1);
    }
    p = realloc(b->pfrb_caddr, minsize * bs);
    if (p == NULL)
      return (-1);
    bzero(p + b->pfrb_msize * bs, (minsize - b->pfrb_msize) * bs);
    b->pfrb_caddr = p;
    b->pfrb_msize = minsize;
  }
  return (0);
}

int
pfr_get_addrs(struct pfr_table *tbl, struct pfr_addr *addr, int *size,
              int flags)
{
  struct pfioc_table io;
  int dev;
  if (tbl == NULL || size == NULL || *size < 0 || (*size && addr == NULL)) {
    errno = EINVAL;
    return (-1);
  }
  bzero(&io, sizeof io);
  io.pfrio_flags = flags;
  io.pfrio_table = *tbl;
  io.pfrio_buffer = addr;
  io.pfrio_esize = sizeof(*addr);
  io.pfrio_size = *size;
  dev = open("/dev/pf", 0);
  if (ioctl(dev, DIOCRGETADDRS, &io)) {
    close(dev);
    return (-1);
  }
  *size = io.pfrio_size;
  close(dev);
  return (0);
}

char *pfr_strerror(int errnum)
{
  switch (errnum) {
  case ESRCH:
    return "Table does not exist";
  case ENOENT:
    return "Anchor or Ruleset does not exist";
  default:
    return strerror(errnum);
  }
}

void *pfr_buf_next(struct pfr_buffer *b, const void *prev)
{
  size_t bs;

  if (b == NULL || b->pfrb_type <= 0 || b->pfrb_type >= PFRB_MAX)
    return (NULL);
  if (b->pfrb_size == 0)
    return (NULL);
  if (prev == NULL)
    return (b->pfrb_caddr);
  bs = buf_esize[b->pfrb_type];
  if ((((caddr_t) prev) - ((caddr_t) b->pfrb_caddr)) / bs >=
      b->pfrb_size - 1)
    return (NULL);
  return (((caddr_t) prev) + bs);
}



int count_table_entries(char *tname, int opts)
{
  struct pfr_table table;
  struct pfr_buffer b, b2;
  int flags = 0;
  void *p;
  int nb_entries = 0;

  bzero(&b, sizeof(b));
  bzero(&b2, sizeof(b2));
  bzero(&table, sizeof(table));

  if (tname != NULL) {
    if (strlcpy(table.pfrt_name, tname,
                sizeof(table.pfrt_name)) >= sizeof(table.pfrt_name))
      return 1;
  }

  b.pfrb_type = PFRB_ADDRS;

  for (;;) {
    pfr_buf_grow(&b, b.pfrb_size);
    b.pfrb_size = b.pfrb_msize;
    RVTEST(pfr_get_addrs(&table, b.pfrb_caddr, &b.pfrb_size, flags));
    if (b.pfrb_size <= b.pfrb_msize)
      break;
  }

  PFRB_FOREACH(p, &b)
      nb_entries++;

  return nb_entries;
}

void radix_perror(void)
{
  extern char *__progname;
  fprintf(stderr, "%s: %s.\n", __progname, pfr_strerror(errno));
}

static const char *config_keys[] = {
  "Table"
};

static int config_keys_num = STATIC_ARRAY_SIZE(config_keys);

struct pf_table {
  char *name;
  struct pf_table *nxt;
};

static struct pf_table *tables = NULL;

struct pf_table *add_table(struct pf_table *src, const char *value)
{
  struct pf_table *new = malloc(sizeof(*new));

  if (new != NULL) {
    new->name = strdup(value);
    new->nxt = NULL;

    if (src == NULL) {
      src = new;
    } else {
      struct pf_table *p = src;
      while (p->nxt != NULL) {
        p = p->nxt;
      }
      p->nxt = new;
    }
  }

  return src;
}

static void submit_gauge(const char *type, const char *type_inst,
                         gauge_t value)
{
  value_t values[1];
  value_list_t vl = VALUE_LIST_INIT;


  values[0].gauge = value;

  vl.values = values;
  vl.values_len = 1;
  sstrncpy(vl.host, hostname_g, sizeof(vl.host));
  sstrncpy(vl.plugin, "pftables", sizeof(vl.plugin));
  sstrncpy(vl.type, type, sizeof(vl.type));
  if (type_inst != NULL)
    sstrncpy(vl.type_instance, type_inst, sizeof(vl.type_instance));

  plugin_dispatch_values(&vl);
}


static int pftables_config(const char *key, const char *value)
{
  if (strcasecmp(key, "Table") == 0) {
    tables = add_table(tables, value);
  }

  return 0;
}

static int pftables_read(void)
{
  struct pf_table *tmp = tables;
  int nb_entries;

  while (tmp != NULL) {
    nb_entries = 0.0;
    nb_entries = count_table_entries(tmp->name, 0);
    submit_gauge("gauge", tmp->name, nb_entries);
    tmp = tmp->nxt;
  }

  return 0;
}

void module_register(void)
{
  plugin_register_config("pftables", pftables_config, config_keys,
                         config_keys_num);
  plugin_register_read("pftables", pftables_read);
}
