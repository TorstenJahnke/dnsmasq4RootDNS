/* dnsmasq is Copyright (c) 2000-2025 Simon Kelley

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; version 2 dated June, 1991, or
   (at your option) version 3 dated 29 June, 2007.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/* Iterative (recursive) DNS resolution against root servers.
   Instead of forwarding queries to an upstream recursive resolver,
   this module implements the iterative resolution algorithm as
   described in RFC 1034 Section 5.3.3:

   1. Start at root servers
   2. Follow NS referrals down the delegation chain
   3. Parse glue records (A/AAAA) from additional section
   4. Repeat until authoritative answer is received

   Inspired by the drill tool from NLnet Labs (ldns library). */

#include "dnsmasq.h"

/* ==================== Delegation Cache ====================
   Caches NS delegation information (zone → server addresses)
   so that subsequent queries for the same TLD/domain can skip
   root and TLD lookups. For example, after resolving www.example.com:
   - "com" → {192.5.6.30, 192.33.14.30, ...}  (TLD servers)
   - "example.com" → {ns1.example.com IP, ...} (auth servers)
   This means a second query for mail.example.com can start at
   the example.com authoritative servers directly. */

static unsigned int deleg_hash(const char *name)
{
  unsigned int hash = 5381;
  const char *p;
  int size = daemon->deleg_cache_size ? daemon->deleg_cache_size : DELEGATION_CACHE_SIZE;

  for (p = name; *p; p++)
    hash = ((hash << 5) + hash) + (unsigned char)(*p | 0x20); /* case-insensitive */

  return hash % size;
}

void deleg_cache_init(void)
{
  int size = daemon->deleg_cache_size ? daemon->deleg_cache_size : DELEGATION_CACHE_SIZE;
  size_t alloc_size;

  daemon->deleg_cache_size = size;

  /* Check for integer overflow in allocation size */
  alloc_size = (size_t)size * sizeof(struct delegation_entry *);
  if (alloc_size / sizeof(struct delegation_entry *) != (size_t)size)
    {
      my_syslog(LOG_ERR, _("recursive: delegation cache size overflow, using default"));
      size = DELEGATION_CACHE_SIZE;
      daemon->deleg_cache_size = size;
      alloc_size = (size_t)size * sizeof(struct delegation_entry *);
    }

  daemon->deleg_cache = whine_malloc(alloc_size);
  if (daemon->deleg_cache)
    {
      memset(daemon->deleg_cache, 0, alloc_size);
      my_syslog(LOG_INFO, _("recursive: delegation cache initialized with %d buckets"), size);
    }
  else
    my_syslog(LOG_ERR, _("recursive: failed to allocate delegation cache (%d buckets)"), size);
}

/* Store a delegation in the cache.
   The server addresses come from the parsed referral_server list.
   ttl_secs specifies how long this entry should be cached (in seconds).
   Use 0 for the default of 1 hour. */
void deleg_cache_store(const char *zone, struct referral_server *servers, time_t ttl_secs)
{
  struct delegation_entry *entry;
  struct referral_server *rs;
  unsigned int h;
  int count;

  if (!daemon->deleg_cache || !zone || !servers)
    return;

  h = deleg_hash(zone);

  /* Check if we already have this zone cached - update if so */
  for (entry = daemon->deleg_cache[h]; entry; entry = entry->next)
    if (hostname_isequal(entry->zone, zone))
      break;

  if (!entry)
    {
      /* Before allocating a new entry, purge any expired entries
	 in this bucket to prevent unbounded memory growth (M1). */
      struct delegation_entry **ep;
      time_t now = time(NULL);
      for (ep = &daemon->deleg_cache[h]; *ep; )
	{
	  if ((*ep)->expires <= now)
	    {
	      struct delegation_entry *dead = *ep;
	      *ep = dead->next;
	      free(dead);
	      daemon->deleg_cache_entries--;
	    }
	  else
	    ep = &(*ep)->next;
	}

      /* Enforce global entry limit to prevent memory exhaustion.
	 Max 10000 entries (root zone has ~1500 TLDs). */
#define DELEGATION_MAX_ENTRIES 10000
      if (daemon->deleg_cache_entries >= DELEGATION_MAX_ENTRIES)
	{
	  if (option_bool(OPT_LOG))
	    my_syslog(LOG_WARNING, _("recursive: delegation cache full (%d entries), not caching '%s'"),
		      daemon->deleg_cache_entries, zone);
	  return;
	}

      /* New entry */
      entry = whine_malloc(sizeof(struct delegation_entry));
      if (!entry)
	return;

      strncpy(entry->zone, zone, MAXDNAME - 1);
      entry->zone[MAXDNAME - 1] = '\0';
      entry->next = daemon->deleg_cache[h];
      daemon->deleg_cache[h] = entry;
      daemon->deleg_cache_entries++;
    }

  /* Store addresses from the referral servers.
     Clear remaining slots to avoid stale data from previous entries. */
  for (count = 0, rs = servers; rs && count < DELEGATION_MAX_ADDRS; rs = rs->next, count++)
    entry->addrs[count] = rs->addr;
  if (count < DELEGATION_MAX_ADDRS)
    memset(&entry->addrs[count], 0,
	   (DELEGATION_MAX_ADDRS - count) * sizeof(union mysockaddr));

  entry->addr_count = count;

  /* Cap TTL to 7 days to prevent overflow and cache poisoning via
     excessively long TTLs. Default is 1 hour for dynamic entries. */
  {
    time_t effective_ttl = (ttl_secs > 0 ? ttl_secs : 3600);
    if (effective_ttl > 604800)
      effective_ttl = 604800; /* 7 days max */
    entry->expires = time(NULL) + effective_ttl;

    if (option_bool(OPT_LOG))
      my_syslog(LOG_INFO, _("recursive: cached delegation for '%s' (%d servers, TTL %lds)"),
		zone, count, (long)effective_ttl);
  }
}

/* Look up the closest enclosing delegation for a domain name.
   Works like drill's set_nss_for_name(): walks up the domain
   hierarchy to find the closest match.

   For "www.example.com" it tries:
   1. "www.example.com" - not found
   2. "example.com" - found! → return those servers
   If "example.com" not found either:
   3. "com" - found! → return those servers

   Returns a newly allocated referral_server list, or NULL if no match. */
struct referral_server *deleg_cache_lookup(const char *name, time_t now)
{
  struct delegation_entry *entry;
  struct referral_server *servers = NULL, *rs;
  const char *lookup;
  int i;

  if (!daemon->deleg_cache || !name)
    return NULL;

  /* Walk up the domain hierarchy */
  for (lookup = name; lookup && *lookup; )
    {
      unsigned int h = deleg_hash(lookup);

      for (entry = daemon->deleg_cache[h]; entry; entry = entry->next)
	{
	  if (hostname_isequal(entry->zone, lookup) && entry->expires > now)
	    {
	      /* Found a valid cached delegation - build server list */
	      for (i = 0; i < entry->addr_count; i++)
		{
		  rs = whine_malloc(sizeof(struct referral_server));
		  if (rs)
		    {
		      rs->addr = entry->addrs[i];
		      rs->next = servers;
		      servers = rs;
		    }
		}

	      if (servers && option_bool(OPT_LOG))
		my_syslog(LOG_INFO, _("recursive: delegation cache hit for '%s' (matched '%s')"),
			  name, lookup);

	      return servers;
	    }
	}

      /* Move up one label: "www.example.com" → "example.com" → "com" */
      lookup = strchr(lookup, '.');
      if (lookup)
	lookup++; /* skip the dot */
    }

  return NULL;
}

/* Root server addresses from IANA (https://www.iana.org/domains/root/servers) */
struct root_hint {
  const char *addr;   /* IPv4 address */
  const char *addr6;  /* IPv6 address */
};

static const struct root_hint root_hints[] = {
  { "198.41.0.4",     "2001:503:ba3e::2:30"  }, /* A.ROOT-SERVERS.NET (Verisign) */
  { "170.247.170.2",  "2801:1b8:10::b"       }, /* B.ROOT-SERVERS.NET (USC-ISI) */
  { "192.33.4.12",    "2001:500:2::c"        }, /* C.ROOT-SERVERS.NET (Cogent) */
  { "199.7.91.13",    "2001:500:2d::d"       }, /* D.ROOT-SERVERS.NET (U Maryland) */
  { "192.203.230.10", "2001:500:a8::e"       }, /* E.ROOT-SERVERS.NET (NASA) */
  { "192.5.5.241",    "2001:500:2f::f"       }, /* F.ROOT-SERVERS.NET (ISC) */
  { "192.112.36.4",   "2001:500:12::d0d"     }, /* G.ROOT-SERVERS.NET (DISA) */
  { "198.97.190.53",  "2001:500:1::53"       }, /* H.ROOT-SERVERS.NET (US Army) */
  { "192.36.148.17",  "2001:7fe::53"         }, /* I.ROOT-SERVERS.NET (Netnod) */
  { "192.58.128.30",  "2001:503:c27::2:30"   }, /* J.ROOT-SERVERS.NET (Verisign) */
  { "193.0.14.129",   "2001:7fd::1"          }, /* K.ROOT-SERVERS.NET (RIPE NCC) */
  { "199.7.83.42",    "2001:500:9f::42"      }, /* L.ROOT-SERVERS.NET (ICANN) */
  { "202.12.27.33",   "2001:dc3::35"         }, /* M.ROOT-SERVERS.NET (WIDE) */
  { NULL, NULL }
};

/* Initialize root servers by adding them to the server list.
   Called at startup when --recursive is enabled. */
void recursive_init_root_servers(void)
{
  const struct root_hint *rh;
  union mysockaddr addr, source_addr;

  my_syslog(LOG_INFO, _("recursive mode: initializing root server hints"));

  for (rh = root_hints; rh->addr; rh++)
    {
      /* Add IPv4 root server */
      memset(&addr, 0, sizeof(addr));
      memset(&source_addr, 0, sizeof(source_addr));
      addr.in.sin_family = AF_INET;
      addr.in.sin_port = htons(NAMESERVER_PORT);
      inet_pton(AF_INET, rh->addr, &addr.in.sin_addr);
      source_addr.in.sin_family = AF_INET;
      source_addr.in.sin_port = htons(0);
      source_addr.in.sin_addr.s_addr = INADDR_ANY;

      add_update_server(0, &addr, &source_addr, NULL, NULL, NULL);

      /* Add IPv6 root server */
      if (rh->addr6)
	{
	  memset(&addr, 0, sizeof(addr));
	  memset(&source_addr, 0, sizeof(source_addr));
	  addr.in6.sin6_family = AF_INET6;
	  addr.in6.sin6_port = htons(NAMESERVER_PORT);
	  inet_pton(AF_INET6, rh->addr6, &addr.in6.sin6_addr);
	  source_addr.in6.sin6_family = AF_INET6;
	  source_addr.in6.sin6_port = htons(0);

	  add_update_server(0, &addr, &source_addr, NULL, NULL, NULL);
	}
    }

  my_syslog(LOG_INFO, _("recursive mode: added %d root servers"),
	    (int)(sizeof(root_hints)/sizeof(root_hints[0]) - 1) * 2);
}

/* Load root server addresses from a hints file.
   The file format is the standard named.root / root.hints format
   used by BIND and available from InterNIC:
   https://www.internic.net/domain/named.root

   Lines starting with ; are comments.
   We look for A and AAAA records and extract the addresses.
   Returns 1 on success, 0 on failure. */
int recursive_load_root_hints(const char *filename)
{
  FILE *fp;
  char line[256];
  union mysockaddr addr, source_addr;
  int count = 0;

  if (!(fp = fopen(filename, "r")))
    {
      my_syslog(LOG_ERR, _("recursive: cannot open root hints file %s: %s"),
		filename, strerror(errno));
      return 0;
    }

  my_syslog(LOG_INFO, _("recursive: loading root hints from %s"), filename);

  while (fgets(line, sizeof(line), fp))
    {
      char name[256], type[16], addr_str[64];
      unsigned int ttl;

      /* Skip comments and empty lines */
      if (line[0] == ';' || line[0] == '#' || line[0] == '\n')
	continue;

      /* Parse lines like:
	 A.ROOT-SERVERS.NET.      3600000      A     198.41.0.4
	 A.ROOT-SERVERS.NET.      3600000      AAAA  2001:503:BA3E::2:30
	 or with class field:
	 .                        3600000      NS    A.ROOT-SERVERS.NET.
	 A.ROOT-SERVERS.NET.      3600000  IN  A     198.41.0.4 */

      /* Try 4-field format first (name ttl type addr) */
      if (sscanf(line, "%255s %u %15s %63s", name, &ttl, type, addr_str) == 4)
	{
	  /* Could be "name ttl IN type" format - check if type is "IN" */
	  if (strcasecmp(type, "IN") == 0)
	    {
	      /* Re-parse as 5-field: name ttl class type addr */
	      char real_type[16];
	      if (sscanf(line, "%*s %*u %*s %15s %63s", real_type, addr_str) == 2)
		{
		  strncpy(type, real_type, sizeof(type) - 1);
		  type[sizeof(type) - 1] = '\0';
		}
	      else
		continue;
	    }
	}
      else
	continue;

      if (strcasecmp(type, "A") == 0)
	{
	  memset(&addr, 0, sizeof(addr));
	  memset(&source_addr, 0, sizeof(source_addr));
	  addr.in.sin_family = AF_INET;
	  addr.in.sin_port = htons(NAMESERVER_PORT);
	  if (inet_pton(AF_INET, addr_str, &addr.in.sin_addr) == 1)
	    {
	      source_addr.in.sin_family = AF_INET;
	      source_addr.in.sin_port = htons(0);
	      source_addr.in.sin_addr.s_addr = INADDR_ANY;
	      add_update_server(0, &addr, &source_addr, NULL, NULL, NULL);
	      count++;
	    }
	}
      else if (strcasecmp(type, "AAAA") == 0)
	{
	  memset(&addr, 0, sizeof(addr));
	  memset(&source_addr, 0, sizeof(source_addr));
	  addr.in6.sin6_family = AF_INET6;
	  addr.in6.sin6_port = htons(NAMESERVER_PORT);
	  if (inet_pton(AF_INET6, addr_str, &addr.in6.sin6_addr) == 1)
	    {
	      source_addr.in6.sin6_family = AF_INET6;
	      source_addr.in6.sin6_port = htons(0);
	      add_update_server(0, &addr, &source_addr, NULL, NULL, NULL);
	      count++;
	    }
	}
    }

  fclose(fp);

  if (count == 0)
    {
      my_syslog(LOG_ERR, _("recursive: no valid root server addresses found in %s"), filename);
      return 0;
    }

  my_syslog(LOG_INFO, _("recursive: loaded %d root server addresses from %s"), count, filename);
  return 1;
}

/* Prime the root server cache (RFC 8109 - DNS Root Priming).
   Sends a connectivity-check NS query for "." to root servers.
   The first real client query will fully prime the delegation cache
   through the normal iterative resolution path. This pre-flight
   check verifies root server reachability at startup. */
void recursive_prime_root(void)
{
  struct dns_header *header;
  unsigned char *p;
  size_t plen;
  struct server *srv;
  int sent = 0;

  /* Find a root server to query.
     Root hint servers are added with flags=0 and no domain (domain_len==0)
     by recursive_init_root_servers() / recursive_load_root_hints(). */
  for (srv = daemon->servers; srv; srv = srv->next)
    if (srv->domain_len == 0 && !(srv->flags & SERV_LITERAL_ADDRESS))
      break;

  if (!srv)
    {
      my_syslog(LOG_WARNING, _("recursive: no root servers available for priming"));
      return;
    }

  my_syslog(LOG_INFO, _("recursive: root priming - sending NS . to verify root server connectivity"));

  /* Build a minimal NS query for the root zone "." */
  header = (struct dns_header *)daemon->packet;
  memset(header, 0, sizeof(struct dns_header));
  header->id = htons(rand16());
  header->hb3 = 0; /* RD=0, standard query */
  header->hb4 = 0;
  header->qdcount = htons(1);

  p = (unsigned char *)(header + 1);
  /* Root name "." = single zero-length label */
  *p++ = 0;
  /* QTYPE = NS (2) */
  PUTSHORT(T_NS, p);
  /* QCLASS = IN (1) */
  PUTSHORT(C_IN, p);
  plen = p - (unsigned char *)header;

  /* Send to root servers as a connectivity check.
     We try up to 4 root servers for redundancy, supporting both IPv4 and IPv6. */
  {
    struct server *s;
    int count = 0;

    for (s = daemon->servers; s && count < 4; s = s->next)
      {
	int fd;

	/* Match root hint servers: no domain, no special flags */
	if (s->domain_len != 0 || (s->flags & SERV_LITERAL_ADDRESS))
	  continue;

	fd = socket(s->addr.sa.sa_family, SOCK_DGRAM, 0);
	if (fd == -1)
	  continue;

	errno = 0;
	while (retry_send(sendto(fd, (char *)header, plen, 0,
				 &s->addr.sa, sa_len(&s->addr))));
	if (errno == 0)
	  sent++;

	close(fd);
	count++;
      }
  }

  if (sent > 0)
    my_syslog(LOG_INFO, _("recursive: root priming queries sent to %d root servers"), sent);
  else
    my_syslog(LOG_WARNING, _("recursive: failed to send root priming queries - check network connectivity"));
}

/* ==================== Root Zone Loading ====================
   Loads the entire root zone file (from InterNIC: root.zone) and
   pre-populates the delegation cache with all ~1500 TLD delegations.
   This eliminates the need to query root servers entirely — every
   query starts directly at the TLD nameservers.

   The root zone file format is standard zone file format:
     com.        172800  IN  NS  a.gtld-servers.net.
     com.        172800  IN  NS  b.gtld-servers.net.
     ...
     a.gtld-servers.net. 172800 IN A  192.5.6.30
     a.gtld-servers.net. 172800 IN AAAA 2001:503:a83e::2:30

   Algorithm (two-pass):
   1. Collect all A/AAAA records into a hostname→IP hash table (glue)
   2. Collect all NS records grouped by zone name
   3. For each zone, resolve NS hostnames to IPs via the glue table
   4. Store in delegation cache with the TTL from the zone file */

/* Temporary structures for root zone parsing */
struct glue_entry {
  char name[MAXDNAME];
  union mysockaddr addr;
  struct glue_entry *next;
};

struct zone_ns_name {
  char ns_name[MAXDNAME];
  struct zone_ns_name *next;
};

struct zone_entry {
  char zone[MAXDNAME];
  unsigned int ttl;
  struct zone_ns_name *ns_names;
  struct zone_entry *next;
};

#define GLUE_HASH_SIZE 4096
#define ZONE_HASH_SIZE 2048

static unsigned int simple_hash(const char *name, int size)
{
  unsigned int hash = 5381;
  const char *p;

  for (p = name; *p; p++)
    hash = ((hash << 5) + hash) + (unsigned char)(*p | 0x20);

  return hash % size;
}

/* Strip trailing dot from a DNS name. Modifies in place. */
static void strip_trailing_dot(char *name)
{
  size_t len = strlen(name);

  if (len > 0 && name[len - 1] == '.')
    name[len - 1] = '\0';
}

/* Look up all IP addresses for a hostname in the glue hash table.
   Returns a referral_server list. */
static struct referral_server *glue_lookup(struct glue_entry **glue_table,
					   const char *hostname)
{
  unsigned int h = simple_hash(hostname, GLUE_HASH_SIZE);
  struct glue_entry *ge;
  struct referral_server *servers = NULL;

  for (ge = glue_table[h]; ge; ge = ge->next)
    {
      if (hostname_isequal(ge->name, hostname))
	{
	  struct referral_server *rs = whine_malloc(sizeof(struct referral_server));
	  if (rs)
	    {
	      rs->addr = ge->addr;
	      rs->next = servers;
	      servers = rs;
	    }
	}
    }

  return servers;
}

int recursive_load_root_zone(const char *path)
{
  FILE *f;
  char line[2048];
  struct glue_entry **glue_table = NULL;
  struct zone_entry **zone_table = NULL;
  int glue_count = 0, ns_count = 0, zones_loaded = 0;
  int i;

  f = fopen(path, "r");
  if (!f)
    {
      my_syslog(LOG_ERR, _("recursive: cannot open root zone file %s: %s"),
		path, strerror(errno));
      return 0;
    }

  my_syslog(LOG_INFO, _("recursive: loading root zone from %s"), path);

  /* Allocate hash tables */
  glue_table = whine_malloc(GLUE_HASH_SIZE * sizeof(struct glue_entry *));
  zone_table = whine_malloc(ZONE_HASH_SIZE * sizeof(struct zone_entry *));
  if (!glue_table || !zone_table)
    {
      if (glue_table) free(glue_table);
      if (zone_table) free(zone_table);
      fclose(f);
      return 0;
    }
  memset(glue_table, 0, GLUE_HASH_SIZE * sizeof(struct glue_entry *));
  memset(zone_table, 0, ZONE_HASH_SIZE * sizeof(struct zone_entry *));

  /* Single pass: read all records, store A/AAAA as glue and NS as zone entries */
  while (fgets(line, sizeof(line), f))
    {
      char name[MAXDNAME], field2[64], field3[16], field4[16], field5[MAXDNAME];
      int fields;
      char *type_str, *rdata_str;
      unsigned int ttl = 0;

      /* Skip comments and empty lines */
      if (line[0] == ';' || line[0] == '\n' || line[0] == '\r')
	continue;

      /* Parse zone file line. Formats:
	 name  TTL  IN  TYPE  RDATA     (5 fields, standard)
	 name  TTL  TYPE  RDATA         (4 fields, no class)  */
      fields = sscanf(line, "%1023s %63s %15s %15s %1023s",
		      name, field2, field3, field4, field5);

      if (fields < 4)
	continue;

      /* Determine field layout */
      if (strcasecmp(field3, "IN") == 0 && fields >= 5)
	{
	  /* Standard: name TTL IN TYPE RDATA */
	  unsigned long parsed_ttl = strtoul(field2, NULL, 10);
	  ttl = (parsed_ttl > 604800) ? 604800 : (unsigned int)parsed_ttl; /* cap at 7 days */
	  type_str = field4;
	  rdata_str = field5;
	}
      else if (fields >= 4)
	{
	  /* No class: name TTL TYPE RDATA */
	  unsigned long parsed_ttl = strtoul(field2, NULL, 10);
	  ttl = (parsed_ttl > 604800) ? 604800 : (unsigned int)parsed_ttl; /* cap at 7 days */
	  type_str = field3;
	  rdata_str = field4;
	}
      else
	continue;

      strip_trailing_dot(name);
      strip_trailing_dot(rdata_str);

      if (strcasecmp(type_str, "A") == 0)
	{
	  struct glue_entry *ge = whine_malloc(sizeof(struct glue_entry));
	  if (ge)
	    {
	      unsigned int h;
	      strncpy(ge->name, name, MAXDNAME - 1);
	      ge->name[MAXDNAME - 1] = '\0';
	      memset(&ge->addr, 0, sizeof(ge->addr));
	      ge->addr.in.sin_family = AF_INET;
	      ge->addr.in.sin_port = htons(NAMESERVER_PORT);
	      if (inet_pton(AF_INET, rdata_str, &ge->addr.in.sin_addr) == 1)
		{
		  h = simple_hash(ge->name, GLUE_HASH_SIZE);
		  ge->next = glue_table[h];
		  glue_table[h] = ge;
		  glue_count++;
		}
	      else
		free(ge);
	    }
	}
      else if (strcasecmp(type_str, "AAAA") == 0)
	{
	  struct glue_entry *ge = whine_malloc(sizeof(struct glue_entry));
	  if (ge)
	    {
	      unsigned int h;
	      strncpy(ge->name, name, MAXDNAME - 1);
	      ge->name[MAXDNAME - 1] = '\0';
	      memset(&ge->addr, 0, sizeof(ge->addr));
	      ge->addr.in6.sin6_family = AF_INET6;
	      ge->addr.in6.sin6_port = htons(NAMESERVER_PORT);
	      if (inet_pton(AF_INET6, rdata_str, &ge->addr.in6.sin6_addr) == 1)
		{
		  h = simple_hash(ge->name, GLUE_HASH_SIZE);
		  ge->next = glue_table[h];
		  glue_table[h] = ge;
		  glue_count++;
		}
	      else
		free(ge);
	    }
	}
      else if (strcasecmp(type_str, "NS") == 0 && name[0] != '\0')
	{
	  /* NS record for a non-root zone (TLD or below).
	     Root NS records (name == "") are skipped - we have those as root hints. */
	  unsigned int h = simple_hash(name, ZONE_HASH_SIZE);
	  struct zone_entry *ze;
	  struct zone_ns_name *nsn;

	  /* Find or create zone entry */
	  for (ze = zone_table[h]; ze; ze = ze->next)
	    if (hostname_isequal(ze->zone, name))
	      break;

	  if (!ze)
	    {
	      ze = whine_malloc(sizeof(struct zone_entry));
	      if (!ze)
		continue;
	      strncpy(ze->zone, name, MAXDNAME - 1);
	      ze->zone[MAXDNAME - 1] = '\0';
	      ze->ttl = ttl;
	      ze->ns_names = NULL;
	      ze->next = zone_table[h];
	      zone_table[h] = ze;
	    }

	  /* Add NS name to this zone */
	  nsn = whine_malloc(sizeof(struct zone_ns_name));
	  if (nsn)
	    {
	      strncpy(nsn->ns_name, rdata_str, MAXDNAME - 1);
	      nsn->ns_name[MAXDNAME - 1] = '\0';
	      nsn->next = ze->ns_names;
	      ze->ns_names = nsn;
	      ns_count++;
	    }
	}
      /* All other record types (DS, DNSKEY, RRSIG, NSEC, SOA) are skipped */
    }

  fclose(f);

  /* Now resolve NS names to IPs and store in delegation cache */
  for (i = 0; i < ZONE_HASH_SIZE; i++)
    {
      struct zone_entry *ze;
      for (ze = zone_table[i]; ze; ze = ze->next)
	{
	  struct referral_server *all_servers = NULL;
	  struct zone_ns_name *nsn;

	  /* For each NS name, look up its A/AAAA addresses in glue table */
	  for (nsn = ze->ns_names; nsn; nsn = nsn->next)
	    {
	      struct referral_server *ns_servers = glue_lookup(glue_table, nsn->ns_name);

	      /* Prepend to the combined list */
	      if (ns_servers)
		{
		  struct referral_server *tail = ns_servers;
		  while (tail->next)
		    tail = tail->next;
		  tail->next = all_servers;
		  all_servers = ns_servers;
		}
	    }

	  if (all_servers)
	    {
	      /* Use the TTL from the zone file (typically 172800 = 2 days) */
	      time_t ttl_secs = ze->ttl > 0 ? (time_t)ze->ttl : 172800;
	      deleg_cache_store(ze->zone, all_servers, ttl_secs);
	      free_referral_servers(all_servers);
	      zones_loaded++;
	    }
	}
    }

  /* Clean up temporary data structures */
  for (i = 0; i < GLUE_HASH_SIZE; i++)
    {
      struct glue_entry *ge = glue_table[i];
      while (ge)
	{
	  struct glue_entry *next = ge->next;
	  free(ge);
	  ge = next;
	}
    }
  free(glue_table);

  for (i = 0; i < ZONE_HASH_SIZE; i++)
    {
      struct zone_entry *ze = zone_table[i];
      while (ze)
	{
	  struct zone_entry *next = ze->next;
	  struct zone_ns_name *nsn = ze->ns_names;
	  while (nsn)
	    {
	      struct zone_ns_name *nn = nsn->next;
	      free(nsn);
	      nsn = nn;
	    }
	  free(ze);
	  ze = next;
	}
    }
  free(zone_table);

  my_syslog(LOG_INFO, _("recursive: loaded %d TLD delegations from root zone "
			 "(%d NS records, %d glue records)"),
	    zones_loaded, ns_count, glue_count);

  return zones_loaded;
}

/* Extract the delegation zone name from a referral response.
   The zone name is the owner name of the first NS record in the
   authority section. For example, if root refers to .com TLD servers,
   the NS record owner is "com."
   Returns 1 if found, 0 otherwise. Zone name stored in 'zone'. */
/* Check if 'name' is equal to or a subdomain of 'domain'.
   For example: "ns1.example.com" is a subdomain of "example.com",
   "example.com" is equal to "example.com",
   "evil.com" is NOT a subdomain of "example.com". */
static int is_name_in_bailiwick(const char *name, const char *domain)
{
  size_t nlen, dlen;

  if (!name || !domain)
    return 0;

  nlen = strlen(name);
  dlen = strlen(domain);

  if (nlen == dlen)
    return hostname_isequal(name, domain);

  if (nlen > dlen && name[nlen - dlen - 1] == '.' &&
      hostname_isequal(name + nlen - dlen, domain))
    return 1;

  return 0;
}

int referral_zone_name(struct dns_header *header, size_t plen, char *zone, size_t zone_len)
{
  unsigned char *p;
  int i;
  unsigned short type, rdlen;
  char tmpzone[MAXDNAME];

  if (zone_len < 1)
    return 0;

  if (!(p = skip_questions(header, plen)))
    return 0;

  /* Skip answer section */
  if (!(p = skip_section(p, ntohs(header->ancount), header, plen)))
    return 0;

  /* Find first NS record in authority section */
  for (i = 0; i < ntohs(header->nscount); i++)
    {
      if (!extract_name(header, plen, &p, tmpzone, EXTR_NAME_EXTRACT, 10))
	return 0;

      GETSHORT(type, p);
      p += 2; /* class */
      p += 4; /* TTL */
      GETSHORT(rdlen, p);

      if (type == T_NS)
	{
	  safe_strncpy(zone, tmpzone, zone_len);
	  return 1;
	}

      if (!ADD_RDLEN(header, p, plen, rdlen))
	return 0;
    }

  return 0;
}

/* Check if a DNS response is a referral.
   A referral has:
   - RCODE = NOERROR
   - Answer section empty (ancount == 0)
   - Authority section contains NS records (nscount > 0)
   - AA (Authoritative Answer) bit is typically NOT set */
int is_referral(struct dns_header *header, size_t plen)
{
  unsigned char *p;
  int i;
  unsigned short type, class, rdlen;
  int has_ns = 0;

  /* Must be NOERROR with no answers */
  if (RCODE(header) != NOERROR)
    return 0;

  if (ntohs(header->ancount) != 0)
    return 0;

  if (ntohs(header->nscount) == 0)
    return 0;

  /* Skip question section */
  if (!(p = skip_questions(header, plen)))
    return 0;

  /* Skip answer section (should be empty, but be safe) */
  if (!(p = skip_section(p, ntohs(header->ancount), header, plen)))
    return 0;

  /* Check authority section for NS records */
  for (i = 0; i < ntohs(header->nscount); i++)
    {
      if (!(p = skip_name(p, header, plen, 10)))
	return 0;

      GETSHORT(type, p);
      GETSHORT(class, p);
      p += 4; /* skip TTL */
      GETSHORT(rdlen, p);

      (void)class;

      if (type == T_NS)
	has_ns = 1;

      if (!ADD_RDLEN(header, p, plen, rdlen))
	return 0;
    }

  return has_ns;
}

/* Parse a referral response and extract server addresses from glue records.

   The authority section contains NS records like:
     example.com. NS ns1.example.com.

   The additional section contains glue A/AAAA records like:
     ns1.example.com. A 1.2.3.4
     ns1.example.com. AAAA 2001:db8::1

   We extract the NS target names, then look up their addresses
   in the additional section. Returns a linked list of referral_server
   structs with the IP addresses. */
/* Maximum number of NS target names to track for glue validation */
#define MAX_NS_NAMES 20

struct referral_server *parse_referral(struct dns_header *header, size_t plen, const char *zone, unsigned long *ns_ttl_out)
{
  unsigned char *p;
  int i;
  unsigned short type, class, rdlen;
  unsigned long rr_ttl;
  unsigned long min_ns_ttl = 0;
  int have_ns_ttl = 0;
  struct referral_server *servers = NULL;
  int server_count = 0;
  int ns_count = ntohs(header->nscount);
  int ar_count = ntohs(header->arcount);
  char (*ns_names)[MAXDNAME] = NULL;
  int ns_name_count = 0;
  char glue_name[MAXDNAME];

  ns_names = whine_malloc(MAX_NS_NAMES * MAXDNAME);
  if (!ns_names)
    return NULL;

  /* Skip question section */
  if (!(p = skip_questions(header, plen)))
    { free(ns_names); return NULL; }

  /* Skip answer section */
  if (!(p = skip_section(p, ntohs(header->ancount), header, plen)))
    { free(ns_names); return NULL; }

  /* First pass: collect NS target names from authority section.
     Only glue records matching these names will be accepted,
     preventing injection of arbitrary A/AAAA records. */
  for (i = 0; i < ns_count; i++)
    {
      char zone_name[MAXDNAME];

      if (!extract_name(header, plen, &p, zone_name, EXTR_NAME_EXTRACT, 10))
	{ free(ns_names); return NULL; }

      GETSHORT(type, p);
      GETSHORT(class, p);
      GETLONG(rr_ttl, p); /* Extract TTL from NS records */
      GETSHORT(rdlen, p);

      (void)class;

      if (type == T_NS && ns_name_count < MAX_NS_NAMES)
	{
	  /* Extract the NS target name (e.g., "ns1.example.com") from RDATA */
	  unsigned char *rdata_p = p;
	  if (extract_name(header, plen, &rdata_p, ns_names[ns_name_count], EXTR_NAME_EXTRACT, 0))
	    {
	      ns_name_count++;
	      /* Track minimum TTL across NS records for delegation caching */
	      if (!have_ns_ttl || rr_ttl < min_ns_ttl)
		{
		  min_ns_ttl = rr_ttl;
		  have_ns_ttl = 1;
		}
	    }
	}

      if (!ADD_RDLEN(header, p, plen, rdlen))
	{ free(ns_names); return NULL; }
    }

  /* Second pass: parse additional section for A/AAAA glue records,
     but only accept records whose owner name matches an NS target. */
  for (i = 0; i < ar_count; i++)
    {
      if (!extract_name(header, plen, &p, glue_name, EXTR_NAME_EXTRACT, 10))
	break;

      GETSHORT(type, p);
      GETSHORT(class, p);
      p += 4; /* skip TTL */
      GETSHORT(rdlen, p);

      (void)class;

      if ((type == T_A && rdlen == INADDRSZ) || (type == T_AAAA && rdlen == IN6ADDRSZ))
	{
	  int matched = 0, j;

	  /* Bailiwick check - only accept glue records for names
	     that are within the parent zone (the zone the responding server
	     is authoritative for). The parent zone is computed by stripping
	     the first label from the delegated zone.
	     Example: delegated zone "nic.de" → parent zone "de"
	     → "ns1.denic.de" is under "de" → glue accepted.
	     → "ns1.google.com" is NOT under "de" → glue rejected.
	     Special case: TLD delegations (zone has no dots, e.g. "com")
	     come from root servers. The parent zone is the root zone,
	     which is authoritative for all names, so all glue is accepted.
	     This is needed because .com NS names (a.gtld-servers.net) are
	     in .net, not .com. */
	  if (zone && *zone)
	    {
	      const char *parent_zone = strchr(zone, '.');
	      if (parent_zone)
		{
		  parent_zone++; /* skip the dot */
		  if (!is_name_in_bailiwick(glue_name, parent_zone))
		    goto skip_rr;
		}
	      /* else: TLD delegation from root - root is authoritative
		 for all names, accept any glue that matches an NS name
		 (NS name matching is checked below). */
	    }

	  /* Limit total glue records to prevent resource exhaustion */
	  if (server_count >= DELEGATION_MAX_ADDRS)
	    goto skip_rr;

	  /* Only accept glue that matches a collected NS target name */
	  for (j = 0; j < ns_name_count; j++)
	    if (hostname_isequal(glue_name, ns_names[j]))
	      {
		matched = 1;
		break;
	      }

	  if (!CHECK_LEN(header, p, plen, rdlen))
	    goto skip_rr;

	  if (matched)
	    {
	      struct referral_server *rs = whine_malloc(sizeof(struct referral_server));
	      if (rs)
		{
		  memset(&rs->addr, 0, sizeof(rs->addr));
		  if (type == T_A)
		    {
		      rs->addr.in.sin_family = AF_INET;
		      rs->addr.in.sin_port = htons(NAMESERVER_PORT);
		      memcpy(&rs->addr.in.sin_addr, p, INADDRSZ);
		    }
		  else
		    {
		      rs->addr.in6.sin6_family = AF_INET6;
		      rs->addr.in6.sin6_port = htons(NAMESERVER_PORT);
		      memcpy(&rs->addr.in6.sin6_addr, p, IN6ADDRSZ);
		    }
		  rs->next = servers;
		  servers = rs;
		  server_count++;
		}
	    }
	}

    skip_rr:
      if (!ADD_RDLEN(header, p, plen, rdlen))
	break;
    }

  if (ns_ttl_out)
    *ns_ttl_out = have_ns_ttl ? min_ns_ttl : 0;

  free(ns_names);
  return servers;
}

/* Build a minimal DNS query packet for the given name and type.
   Returns the packet length, or 0 on failure. */
static size_t build_dns_query(unsigned char *buf, size_t buflen, const char *name, unsigned short qtype)
{
  struct dns_header *header = (struct dns_header *)buf;
  unsigned char *p;

  if (buflen < sizeof(struct dns_header) + strlen(name) + 2 + 4)
    return 0;

  memset(header, 0, sizeof(struct dns_header));
  header->id = htons(rand16());
  header->hb3 = 0;  /* No RD - iterative query */
  header->qdcount = htons(1);

  p = (unsigned char *)(header + 1);
  p = do_rfc1035_name(p, name, NULL);
  if (!p)
    return 0;
  *p++ = 0; /* root label terminator */

  PUTSHORT(qtype, p);
  PUTSHORT(C_IN, p);

  return (size_t)(p - buf);
}

/* Extract A/AAAA addresses from the answer section of a DNS response.
   Returns a referral_server list, or NULL if no addresses found. */
struct referral_server *extract_addresses_from_answer(struct dns_header *header, size_t plen)
{
  unsigned char *p;
  int i;
  struct referral_server *servers = NULL;
  int count = 0;

  if (RCODE(header) != NOERROR || ntohs(header->ancount) == 0)
    return NULL;

  if (!(p = skip_questions(header, plen)))
    return NULL;

  for (i = 0; i < ntohs(header->ancount) && count < DELEGATION_MAX_ADDRS; i++)
    {
      unsigned short type, rdlen;
      char name[MAXDNAME];

      if (!extract_name(header, plen, &p, name, EXTR_NAME_EXTRACT, 10))
        break;

      GETSHORT(type, p);
      p += 2; /* class */
      p += 4; /* TTL */
      GETSHORT(rdlen, p);

      if ((type == T_A && rdlen == INADDRSZ) || (type == T_AAAA && rdlen == IN6ADDRSZ))
        {
          struct referral_server *rs = whine_malloc(sizeof(struct referral_server));
          if (rs)
            {
              memset(&rs->addr, 0, sizeof(rs->addr));
              if (type == T_A)
                {
                  rs->addr.in.sin_family = AF_INET;
                  rs->addr.in.sin_port = htons(NAMESERVER_PORT);
                  memcpy(&rs->addr.in.sin_addr, p, INADDRSZ);
                }
              else
                {
                  rs->addr.in6.sin6_family = AF_INET6;
                  rs->addr.in6.sin6_port = htons(NAMESERVER_PORT);
                  memcpy(&rs->addr.in6.sin6_addr, p, IN6ADDRSZ);
                }
              rs->next = servers;
              servers = rs;
              count++;
            }
        }

      if (!ADD_RDLEN(header, p, plen, rdlen))
        break;
    }

  return servers;
}

/* Synchronously resolve an NS name by sending iterative UDP queries.
   Uses the delegation cache for starting servers, follows referrals,
   returns resolved addresses as referral_server list.
   This handles the out-of-bailiwick case where a delegation response
   contains NS records (e.g., ns1.google.com) but no glue records
   because the NS names are outside the delegated zone. */
struct referral_server *resolve_ns_name_sync(const char *ns_name)
{
  struct referral_server *target_servers, *rs;
  ALIGNED(sizeof(u16)) unsigned char query_buf[1280]; /* enough for query + EDNS */
  ALIGNED(sizeof(u16)) unsigned char resp_buf[4096]; /* response buffer */
  size_t qlen;
  int iteration;
  time_t now = time(NULL);

  if (option_bool(OPT_LOG))
    my_syslog(LOG_INFO, _("recursive: resolving out-of-bailiwick NS name '%s'"), ns_name);

  /* Build A query for the NS name */
  qlen = build_dns_query(query_buf, sizeof(query_buf), ns_name, T_A);
  if (!qlen)
    return NULL;

  /* Find starting servers from delegation cache */
  target_servers = deleg_cache_lookup(ns_name, now);
  if (!target_servers)
    {
      /* No delegation cache entry - would need root servers.
         For now, return NULL; the main query will retry later
         when delegations are cached from other queries. */
      if (option_bool(OPT_LOG))
        my_syslog(LOG_INFO, _("recursive: no cached delegation for NS name '%s'"), ns_name);
      return NULL;
    }

  for (iteration = 0; iteration < 10; iteration++)
    {
      int fd = -1;
      struct pollfd pfd;
      ssize_t n = 0;
      struct dns_header *resp_header;
      int got_response = 0;

      /* Try each server until we get a response */
      for (rs = target_servers; rs && !got_response; rs = rs->next)
        {
          fd = socket(rs->addr.sa.sa_family, SOCK_DGRAM | SOCK_NONBLOCK, 0);
          if (fd == -1)
            continue;

          /* Update query ID for each attempt */
          ((struct dns_header *)query_buf)->id = htons(rand16());

          if (sendto(fd, query_buf, qlen, 0, &rs->addr.sa, sa_len(&rs->addr)) < 0)
            {
              close(fd);
              continue;
            }

          /* Wait for response with 250ms timeout (reduced from 2s to minimize
             eventloop blocking - this function runs synchronously) */
          pfd.fd = fd;
          pfd.events = POLLIN;
          if (poll(&pfd, 1, 250) > 0 && (pfd.revents & POLLIN))
            {
              n = recv(fd, resp_buf, sizeof(resp_buf), 0);
              if (n >= (ssize_t)sizeof(struct dns_header))
                got_response = 1;
            }

          close(fd);
        }

      if (!got_response)
        {
          free_referral_servers(target_servers);
          return NULL;
        }

      resp_header = (struct dns_header *)resp_buf;

      /* Check if we got an answer */
      if (RCODE(resp_header) == NOERROR && ntohs(resp_header->ancount) > 0)
        {
          struct referral_server *result = extract_addresses_from_answer(resp_header, (size_t)n);
          free_referral_servers(target_servers);
          if (result && option_bool(OPT_LOG))
            my_syslog(LOG_INFO, _("recursive: resolved NS name '%s' successfully"), ns_name);
          return result;
        }

      /* Check if this is a referral - follow it */
      if (is_referral(resp_header, (size_t)n))
        {
          char zone[MAXDNAME];
          struct referral_server *new_servers;

          zone[0] = '\0';
          referral_zone_name(resp_header, (size_t)n, zone, sizeof(zone));

          /* Try to get glue from this referral (might be in-bailiwick at this level) */
          {
            unsigned long sync_ns_ttl = 0;
            new_servers = parse_referral(resp_header, (size_t)n, zone, &sync_ns_ttl);
            if (!new_servers)
              {
                /* Still no glue - try without bailiwick restriction for this sub-resolution */
                new_servers = parse_referral(resp_header, (size_t)n, NULL, &sync_ns_ttl);
              }

            if (new_servers)
              {
                /* Cache this delegation with TTL from referral NS records */
                if (zone[0] != '\0')
                  deleg_cache_store(zone, new_servers, (time_t)sync_ns_ttl);

              free_referral_servers(target_servers);
              target_servers = new_servers;
              continue;
            }
          }
        }

      /* NXDOMAIN or other error */
      break;
    }

  free_referral_servers(target_servers);
  return NULL;
}

/* Extract NS target names from the authority section of a referral response.
   Returns the number of names extracted. Names are written to ns_names array.
   Caller provides pre-allocated array of ns_names[max_names][MAXDNAME]. */
int extract_referral_ns_names(struct dns_header *header, size_t plen,
                              char ns_names[][MAXDNAME], int max_names)
{
  unsigned char *p;
  int i, count = 0;
  unsigned short type, rdlen;

  if (!(p = skip_questions(header, plen)))
    return 0;

  if (!(p = skip_section(p, ntohs(header->ancount), header, plen)))
    return 0;

  for (i = 0; i < ntohs(header->nscount) && count < max_names; i++)
    {
      char zone_name[MAXDNAME];

      if (!extract_name(header, plen, &p, zone_name, EXTR_NAME_EXTRACT, 10))
        break;

      GETSHORT(type, p);
      p += 2; /* class */
      p += 4; /* TTL */
      GETSHORT(rdlen, p);

      if (type == T_NS)
        {
          unsigned char *rdata_p = p;
          if (extract_name(header, plen, &rdata_p, ns_names[count], EXTR_NAME_EXTRACT, 0))
            count++;
        }

      if (!ADD_RDLEN(header, p, plen, rdlen))
        break;
    }

  return count;
}

/* Extract the final CNAME target from a response's answer section.
   Follows CNAME chains to find the last target.
   If ttl_out is non-NULL, stores the TTL of the last CNAME found.
   Returns 1 if found, 0 if no CNAME in answer section. */
int extract_cname_target(struct dns_header *header, size_t plen,
                         char *target, size_t target_len,
                         unsigned long *ttl_out)
{
  unsigned char *p;
  int i, found = 0;
  unsigned short type, rdlen;
  unsigned long ttl;
  char current_name[MAXDNAME];

  (void)target_len;

  if (!(p = skip_questions(header, plen)))
    return 0;

  /* Extract the queried name to start the chain */
  extract_request(header, plen, current_name, NULL, NULL);

  for (i = 0; i < ntohs(header->ancount); i++)
    {
      char rr_name[MAXDNAME];
      unsigned char *save_p;

      if (!extract_name(header, plen, &p, rr_name, EXTR_NAME_EXTRACT, 10))
        break;

      GETSHORT(type, p);
      p += 2; /* class */
      GETLONG(ttl, p);
      GETSHORT(rdlen, p);
      save_p = p;

      if (type == T_CNAME && hostname_isequal(rr_name, current_name))
        {
          if (extract_name(header, plen, &save_p, current_name, EXTR_NAME_EXTRACT, 0))
            {
              found = 1;
              if (ttl_out)
                *ttl_out = ttl;
            }
        }

      if (!ADD_RDLEN(header, p, plen, rdlen))
        break;
    }

  if (found)
    safe_strncpy(target, current_name, MAXDNAME);

  return found;
}

/* Free a linked list of referral servers. */
void free_referral_servers(struct referral_server *servers)
{
  struct referral_server *tmp;

  while (servers)
    {
      tmp = servers;
      servers = servers->next;
      free(tmp);
    }
}

/* Check if a response came from one of the referral servers
   stored in the frec. Returns 1 if match found, 0 otherwise. */
int recursive_validate_source(struct frec *forward, union mysockaddr *addr)
{
  struct referral_server *rs;

  if (!forward || !(forward->flags & FREC_RECURSIVE) || !forward->referral_servers)
    return 0;

  for (rs = forward->referral_servers; rs; rs = rs->next)
    if (sockaddr_isequal(&rs->addr, addr))
      return 1;

  return 0;
}
