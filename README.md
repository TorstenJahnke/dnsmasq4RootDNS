# DNSMASQ RootDNS Edition

**Iterative DNS Resolution from Root Servers — No Forwarders Required**

A modified version of [dnsmasq](http://www.thekelleys.org.uk/dnsmasq/doc.html) (v2.92) that resolves DNS queries **directly against the DNS root servers**, implementing the iterative resolution algorithm defined in [RFC 1034 §5.3.3](https://www.rfc-editor.org/rfc/rfc1034).

Speeds up DNS resolution by up to **4×** compared to public resolvers — once the delegation cache is warm, most queries skip root and TLD lookups entirely. No third-party resolver dependency, no centralized query logging, no DNS-based censorship. Queries are distributed across authoritative servers — no single entity sees your full resolution profile. DNSSEC validation is fully supported but optional (`--wipe-dnssec`).

```
Traditional dnsmasq:
  Client → dnsmasq → Forwarder (8.8.8.8) → Answer

dnsmasq-Root (iterative):
  Client → dnsmasq → Root Server → TLD Server → Auth Server → Answer

dnsmasq-Root (with pre-loaded root zone):
  Client → dnsmasq → TLD Server → Auth Server → Answer
                      (root servers skipped entirely)
```

---

## Quick Start

```bash
# Build (standard, no external dependencies)
make            # just build it and have fun
make help       # see all build targets and options

# Run — resolves iteratively from root servers
dnsmasq --forward-rootDNS --cache-size=50000
```

For full-featured builds with DNSSEC, DBus, IDN2, and more, see [Building](#building).

---

## How It Works

When `--forward-rootDNS` is enabled, dnsmasq follows the DNS delegation chain instead of forwarding to an upstream resolver:

1. Query a **root server** for `www.example.com`
2. Root refers to `.com` TLD servers (NS referral + glue records)
3. Query `.com` TLD server → refers to `example.com` authoritative servers
4. Query `example.com` authoritative server → final answer
5. Cache the answer **and** the delegation path for future queries

Outgoing queries have the RD (Recursion Desired) bit cleared. Responses to clients have the RA (Recursion Available) bit set. Referral chain depth is limited to 20 iterations for loop protection.

---

## Command-Line Options

### `--forward-rootDNS`

Main switch. Enables iterative resolution from root servers. Loads the 13 IANA root server addresses (A–M, IPv4 + IPv6). No `--server=` configuration needed.

```bash
dnsmasq --forward-rootDNS
```

### `--with-root-hints=<path>`

Load root server addresses from a hints file instead of the built-in defaults. Uses the standard InterNIC [`named.root`](https://www.internic.net/domain/named.root) format.

```bash
dnsmasq --forward-rootDNS --with-root-hints=/etc/dnsmasq/named.root
```

### `--with-root-zone=<path>`

Pre-load the entire root zone into the delegation cache at startup. Eliminates root server queries entirely — every lookup starts directly at the TLD nameservers. Download from [InterNIC](https://www.internic.net/domain/root.zone).

```bash
dnsmasq --forward-rootDNS --with-root-zone=/etc/dnsmasq/root.zone
```

At startup, the parser reads all A/AAAA glue records, groups NS records by zone, resolves NS hostnames to IPs, and stores ~1,500 TLD delegations in the delegation cache.

### `--with-root-priming`

Send a root priming query (`NS .`) at startup to verify root server connectivity ([RFC 8109](https://www.rfc-editor.org/rfc/rfc8109)). Enabled by default when `--forward-rootDNS` is active.

### `--wipe-dnssec`

Strip all DNSSEC-related records (DS, RRSIG, NSEC, DNSKEY, NSEC3, NSEC3PARAM) from responses before returning them to clients. Also clears the AD bit. Useful when the root zone is loaded from a trusted local file and DNSSEC validation is unnecessary.

```bash
dnsmasq --forward-rootDNS --with-root-zone=/etc/root.zone --wipe-dnssec
```

### `--cname-flattening`

Flatten CNAME chains in recursive responses. Instead of returning the full chain (`alias → intermediate → … → target A 1.2.3.4`), the client receives only the final A/AAAA records rewritten under the original query name. The CNAME chain is hidden entirely.

```
Without flattening:
  sub.example.com  CNAME  cdn.example.com
  cdn.example.com  CNAME  edge.provider.com
  edge.provider.com  A    1.2.3.4

With --cname-flattening:
  sub.example.com  A  1.2.3.4
```

```bash
dnsmasq --forward-rootDNS --cname-flattening
```

### `--cname-minimization`

Minimize CNAME chains in recursive responses. Multi-hop chains are collapsed to a single CNAME from the original query name directly to the final target, followed by the answer records. Intermediate hops are stripped.

```
Without minimization:
  sub.example.com  CNAME  cdn.example.com
  cdn.example.com  CNAME  edge.provider.com
  edge.provider.com  A    1.2.3.4

With --cname-minimization:
  sub.example.com  CNAME  edge.provider.com
  edge.provider.com  A    1.2.3.4
```

```bash
dnsmasq --forward-rootDNS --cname-minimization
```

**Note:** `--cname-flattening` and `--cname-minimization` are mutually exclusive. If both are set, `--cname-flattening` takes precedence.

### `--deleg-cache-size=<entries>`

Number of hash buckets for the delegation cache. Default: **4096**, minimum: 64.

### `--iterative-async=<N>`

Maximum number of concurrent asynchronous NS resolutions. When the iterative resolver encounters out-of-bailiwick NS names (nameserver hostnames without glue records), it must resolve those names before it can continue the delegation chain. By default, this is done asynchronously — a sub-query is dispatched and the event loop continues serving other clients while the NS name is resolved in the background.

| Value | Behavior |
|-------|----------|
| 0     | Synchronous only — blocks the event loop during NS resolution |
| 1     | One async resolution at a time |
| **2** (default) | **Recommended** — up to 2 concurrent async NS resolutions |
| 3–10  | Higher concurrency (diminishing returns above 3) |

Default: **2** (auto-enabled with `--forward-rootDNS`). Set to **0** to force synchronous NS resolution.

```bash
dnsmasq --forward-rootDNS --iterative-async=3
```

**Note:** Async NS resolution is relevant in all modes (root hints, root zone, priming). Out-of-bailiwick NS names can appear at any level of the delegation chain, not just at the root level.

### `--all-servers` vs `--iterative-async=<N>`

These two options are often confused but solve completely different problems:

| | `--all-servers` | `--iterative-async=<N>` |
|---|---|---|
| **Purpose** | Send the same query to multiple upstream **forwarders** simultaneously | Resolve NS hostnames concurrently during **iterative** resolution |
| **Mode** | Forwarder mode (`--server=8.8.8.8 --server=1.1.1.1`) | Iterative mode (`--forward-rootDNS`) |
| **What it parallelizes** | Identical queries to competing forwarders — fastest answer wins | Sub-queries for out-of-bailiwick NS names within a single delegation chain |
| **Goal** | Reduce latency by racing forwarders against each other | Keep the event loop responsive while resolving NS hostnames that lack glue records |
| **Typical use case** | Multiple ISP resolvers or public DNS services configured | Iterative resolution from root servers |

**`--all-servers`** is a standard dnsmasq option for **forwarder mode**. When you configure multiple upstream servers (`--server=8.8.8.8 --server=1.1.1.1`), dnsmasq normally picks one. With `--all-servers`, it sends the query to **all** of them and returns whichever answer arrives first. This is pure forwarder racing — dnsmasq does no resolution itself.

**`--iterative-async=<N>`** is a RootDNS option for **iterative mode**. During iterative resolution, the resolver sometimes encounters NS records that point to hostnames without accompanying IP addresses (no glue). Before it can continue the delegation chain, it must resolve those NS hostnames — a completely separate DNS lookup. With `--iterative-async`, these sub-lookups run asynchronously so the event loop can serve other clients in the meantime.

```
--all-servers (forwarder mode):
  Client query "example.com"
    → send to 8.8.8.8  ──┐
    → send to 1.1.1.1  ──┤  race: fastest wins
    → send to 9.9.9.9  ──┘

--iterative-async (iterative mode):
  Client query "example.com"
    → root says: ask ns1.tld-servers.net (no glue — IP unknown)
      → async sub-query: resolve ns1.tld-servers.net  ← runs in background
      → event loop continues serving other clients
      → sub-query returns IP → continue delegation chain
```

**They are mutually exclusive by design.** `--all-servers` requires `--server=` forwarders. `--iterative-async` requires `--forward-rootDNS`. Using both makes no sense — if you resolve iteratively, there are no forwarders to race.

---

## Caching Architecture

dnsmasq-Root uses two independent caches:

### Standard DNS Cache (`--cache-size`)

The existing dnsmasq answer cache for final resolved records (A, AAAA, MX, CNAME, etc.). When a cached answer exists, no network query is needed.

| `--cache-size`  | Approx. RAM | Use Case                    |
|-----------------|-------------|-----------------------------|
| 150 (default)   | ~0.5 MB     | Minimal / testing           |
| 10,000          | ~2 MB       | Small home network          |
| 50,000          | ~10 MB      | **Recommended** with `--forward-rootDNS` |
| 500,000         | ~100 MB     | Large network / ISP         |
| 5,000,000 (max) | ~1 GB       | Hard limit                  |

The >10,000 warning is suppressed when `--forward-rootDNS` is active, since larger caches are beneficial for iterative resolution. Each entry uses ~100–200 bytes on average.

### Delegation Cache (`--deleg-cache-size`)

New cache for NS delegation paths — which nameservers are authoritative for which zones:

```
"com"         → {192.5.6.30, 192.33.14.30, ...}
"example.com" → {ns1.example.com IP, ns2.example.com IP}
```

A query for `mail.example.com` skips root and `.com` lookups if the `example.com` delegation is already cached. Each entry supports up to 13 NS addresses and uses ~1.4 KB.

| `--deleg-cache-size` | Approx. RAM | Notes                              |
|----------------------|-------------|------------------------------------|
| 64 (minimum)         | ~0.1 MB     | Small, many hash collisions        |
| 4,096 (default)      | ~5.5 MB     | Good for most deployments          |
| 8,192                | ~11 MB      | **Recommended** with `--with-root-zone` |

With `--with-root-zone`, ~1,500 TLD delegations are loaded at startup (~2.1 MB regardless of bucket count). Dynamic entries use the TTL from referral NS records (honoring the authoritative server's TTL); pre-loaded entries use the zone file TTL (capped at 7 days).

---

## Performance Optimizations

Several optimizations reduce latency for iterative resolution:

- **TTL from referral NS records:** The delegation cache now stores entries with the actual TTL from NS referral responses instead of a fixed default. This means popular delegations stay cached as long as the authoritative server intends, while stale entries expire naturally.

- **CNAME Additional Section shortcut:** When following CNAME chains, if the referral response already contains the target A/AAAA records in its Additional section, the resolver uses them directly instead of starting a new delegation chase. This avoids unnecessary round-trips for common CDN patterns.

- **Async NS resolution:** Out-of-bailiwick NS names are resolved asynchronously (see `--iterative-async`), preventing the event loop from blocking while waiting for NS address lookups. Other clients continue to be served during these resolutions.

---

## Recommended Configurations

### Full DNSSEC Validation (recommended)

```ini
# /etc/dnsmasq.conf
forward-rootDNS
with-root-zone=/etc/dnsmasq/root.zone
no-resolv
no-hosts
dnssec
dnssec-check-unsigned
trust-anchor=.,20326,8,2,E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D
trust-anchor=.,38696,8,2,683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16
cache-size=50000
deleg-cache-size=8192
```

Resolves iteratively with full chain-of-trust validation. Signed domains get the AD flag, bogus signatures return SERVFAIL.

### Maximum Performance (no DNSSEC)

```ini
forward-rootDNS
with-root-zone=/etc/dnsmasq/root.zone
wipe-dnssec
cache-size=50000
deleg-cache-size=8192
```

### Standard Iterative Resolution

```ini
forward-rootDNS
cache-size=50000
```

### With CNAME Flattening

```ini
forward-rootDNS
with-root-zone=/etc/dnsmasq/root.zone
cname-flattening
cache-size=50000
deleg-cache-size=8192
```

Clients see direct A/AAAA answers without any CNAME indirection. Useful for CDN-heavy environments where CNAME chains add unnecessary response size.

### With Custom Root Hints

```ini
forward-rootDNS
with-root-hints=/etc/dnsmasq/named.root
cache-size=50000
```

---

## Updating the Root Zone

The root zone should be updated periodically (e.g. weekly via cron):

```bash
curl -o /etc/dnsmasq/root.zone https://www.internic.net/domain/root.zone
systemctl restart dnsmasq
```

---

## Building

```bash
make help    # show all available targets and flags
```

| Target              | Description                                          |
|---------------------|------------------------------------------------------|
| `make`              | Standard build, no external dependencies             |
| `make debian`       | Debian/Ubuntu — all features (DNSSEC, DBus, IDN2, conntrack, nftset, Lua) |
| `make debian-hardened` | + FORTIFY_SOURCE, stack protector, PIE, full RELRO, LTO |
| `make debian-native`   | + native CPU tuning                               |
| `make freebsd`      | FreeBSD — all features (DNSSEC, DBus, IDN2, Lua)     |
| `make freebsd-hardened` | + security hardening, LTO                        |

### Build Dependencies

**Debian/Ubuntu:**
```bash
sudo apt install libdbus-1-dev libidn2-dev libnetfilter-conntrack-dev \
                 libnftables-dev nettle-dev libgmp-dev liblua5.4-dev
```

**FreeBSD:**
```bash
pkg install dbus libidn2 nettle gmp lua54
```

Binary output: `src/dnsmasq`

---

## References

- [RFC 1034](https://www.rfc-editor.org/rfc/rfc1034) — Domain Names: Concepts and Facilities (§5.3.3: Iterative Resolution)
- [RFC 4033](https://www.rfc-editor.org/rfc/rfc4033) — DNS Security Introduction and Requirements (DNSSEC)
- [RFC 4035](https://www.rfc-editor.org/rfc/rfc4035) — Protocol Modifications for DNSSEC
- [RFC 8109](https://www.rfc-editor.org/rfc/rfc8109) — Initializing a DNS Resolver with Priming Queries
- [IANA Root Servers](https://www.iana.org/domains/root/servers)
- [InterNIC Root Zone](https://www.internic.net/domain/root.zone)
- [dnsmasq](http://www.thekelleys.org.uk/dnsmasq/doc.html) — Original project by Simon Kelley

## License

Based on [dnsmasq](http://www.thekelleys.org.uk/dnsmasq/doc.html) by Simon Kelley.

- Original dnsmasq: Copyright © Simon Kelley, GNU GPL v2 or v3
- RootDNS modifications: Copyright © 2026 Aviontex GmbH, Germany (Torsten Jahnke)

Licensed under the GNU General Public License v2 (or, at your option, v3).
See COPYING for details.

**THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.**
