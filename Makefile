# dnsmasq is Copyright (c) 2000-2025 Simon Kelley
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; version 2 dated June, 1991, or
#  (at your option) version 3 dated 29 June, 2007.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#    
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see <http://www.gnu.org/licenses/>.

# NOTE: Building the i18n targets requires GNU-make 


# Variables you may well want to override.

PREFIX        = /usr/local
BINDIR        = $(PREFIX)/sbin
MANDIR        = $(PREFIX)/share/man
LOCALEDIR     = $(PREFIX)/share/locale
BUILDDIR      = $(SRC)
DESTDIR       = 
CFLAGS        = -Wall -W -O2
LDFLAGS       = 
COPTS         = 
RPM_OPT_FLAGS = 
LIBS          = 
LUA           = lua

#################################################################

# Variables you might want to override.

PKG_CONFIG = pkg-config
INSTALL    = install
MSGMERGE   = msgmerge
MSGFMT     = msgfmt
XGETTEXT   = xgettext

SRC = src
PO  = po
MAN = man

#################################################################

# pmake way. (NB no spaces to keep gmake 3.82 happy)
top!=pwd
# GNU make way.
top?=$(CURDIR)

dbus_cflags =   `echo $(COPTS) | $(top)/bld/pkg-wrapper HAVE_DBUS $(PKG_CONFIG) --cflags dbus-1` 
dbus_libs =     `echo $(COPTS) | $(top)/bld/pkg-wrapper HAVE_DBUS $(PKG_CONFIG) --libs dbus-1` 
ubus_libs =     `echo $(COPTS) | $(top)/bld/pkg-wrapper HAVE_UBUS "" --copy '-lubox -lubus'`
idn_cflags =    `echo $(COPTS) | $(top)/bld/pkg-wrapper HAVE_IDN $(PKG_CONFIG) --cflags libidn` 
idn_libs =      `echo $(COPTS) | $(top)/bld/pkg-wrapper HAVE_IDN $(PKG_CONFIG) --libs libidn` 
idn2_cflags =   `echo $(COPTS) | $(top)/bld/pkg-wrapper HAVE_LIBIDN2 $(PKG_CONFIG) --cflags libidn2`
idn2_libs =     `echo $(COPTS) | $(top)/bld/pkg-wrapper HAVE_LIBIDN2 $(PKG_CONFIG) --libs libidn2`
ct_cflags =     `echo $(COPTS) | $(top)/bld/pkg-wrapper HAVE_CONNTRACK $(PKG_CONFIG) --cflags libnetfilter_conntrack`
ct_libs =       `echo $(COPTS) | $(top)/bld/pkg-wrapper HAVE_CONNTRACK $(PKG_CONFIG) --libs libnetfilter_conntrack`
lua_cflags =    `echo $(COPTS) | $(top)/bld/pkg-wrapper HAVE_LUASCRIPT $(PKG_CONFIG) --cflags $(LUA)` 
lua_libs =      `echo $(COPTS) | $(top)/bld/pkg-wrapper HAVE_LUASCRIPT $(PKG_CONFIG) --libs $(LUA)` 
nettle_cflags = `echo $(COPTS) | $(top)/bld/pkg-wrapper HAVE_DNSSEC     $(PKG_CONFIG) --cflags 'nettle hogweed'`
nettle_libs =   `echo $(COPTS) | $(top)/bld/pkg-wrapper HAVE_DNSSEC     $(PKG_CONFIG) --libs 'nettle hogweed'`
gmp_libs =      `echo $(COPTS) | $(top)/bld/pkg-wrapper HAVE_DNSSEC NO_GMP --copy -lgmp`
sunos_libs =    `if uname | grep SunOS >/dev/null 2>&1; then echo -lsocket -lnsl -lposix4; fi`
nft_cflags =    `echo $(COPTS) | $(top)/bld/pkg-wrapper HAVE_NFTSET $(PKG_CONFIG) --cflags libnftables` 
nft_libs =      `echo $(COPTS) | $(top)/bld/pkg-wrapper HAVE_NFTSET $(PKG_CONFIG) --libs libnftables`
version =       -DVERSION='\"`$(top)/bld/get-version $(top)` (RootDNS Fork Edition)\"'

sum?=$(shell echo $(CC) -DDNSMASQ_COMPILE_FLAGS="$(CFLAGS)" -DDNSMASQ_COMPILE_OPTS $(COPTS) -E $(top)/$(SRC)/dnsmasq.h | ( md5sum 2>/dev/null || md5 ) | cut -f 1 -d ' ')
sum!=echo $(CC) -DDNSMASQ_COMPILE_FLAGS="$(CFLAGS)" -DDNSMASQ_COMPILE_OPTS $(COPTS) -E $(top)/$(SRC)/dnsmasq.h | ( md5sum 2>/dev/null || md5 ) | cut -f 1 -d ' '
copts_conf = .copts_$(sum)

objs = cache.o rfc1035.o util.o option.o forward.o network.o \
       dnsmasq.o dhcp.o lease.o rfc2131.o netlink.o dbus.o bpf.o \
       helper.o tftp.o log.o conntrack.o dhcp6.o rfc3315.o \
       dhcp-common.o outpacket.o radv.o slaac.o auth.o ipset.o pattern.o \
       domain.o dnssec.o blockdata.o tables.o loop.o inotify.o \
       poll.o rrfilter.o edns0.o arp.o crypto.o dump.o ubus.o \
       metrics.o domain-match.o nftset.o recursive.o

hdrs = dnsmasq.h config.h dhcp-protocol.h dhcp6-protocol.h \
       dns-protocol.h radv-protocol.h ip6addr.h metrics.h

all : $(BUILDDIR)
	@cd $(BUILDDIR) && $(MAKE) \
 top="$(top)" \
 build_cflags="$(version) $(dbus_cflags) $(idn2_cflags) $(idn_cflags) $(ct_cflags) $(lua_cflags) $(nettle_cflags) $(nft_cflags)" \
 build_libs="$(dbus_libs) $(idn2_libs) $(idn_libs) $(ct_libs) $(lua_libs) $(sunos_libs) $(nettle_libs) $(gmp_libs) $(ubus_libs) $(nft_libs)" \
 -f $(top)/Makefile dnsmasq 

mostly_clean :
	rm -f $(BUILDDIR)/*.mo $(BUILDDIR)/*.pot 
	rm -f $(BUILDDIR)/.copts_* $(BUILDDIR)/*.o $(BUILDDIR)/dnsmasq.a $(BUILDDIR)/dnsmasq

clean : mostly_clean
	rm -f $(BUILDDIR)/dnsmasq_baseline
	rm -f core */core
	rm -f *~ contrib/*/*~ */*~

install : all
	$(INSTALL) -d $(DESTDIR)$(BINDIR)
	$(INSTALL) -d $(DESTDIR)$(MANDIR)/man8
	$(INSTALL) -m 644 $(MAN)/dnsmasq.8 $(DESTDIR)$(MANDIR)/man8 
	$(INSTALL) -m 755 $(BUILDDIR)/dnsmasq $(DESTDIR)$(BINDIR)

all-i18n : $(BUILDDIR)
	@cd $(BUILDDIR) && $(MAKE) \
 top="$(top)" \
 i18n=-DLOCALEDIR=\'\"$(LOCALEDIR)\"\' \
 build_cflags="$(version) $(dbus_cflags) $(idn2_cflags) $(idn_cflags) $(ct_cflags) $(lua_cflags) $(nettle_cflags) $(nft_cflags)" \
 build_libs="$(dbus_libs) $(idn2_libs) $(idn_libs) $(ct_libs) $(lua_libs) $(sunos_libs) $(nettle_libs) $(gmp_libs) $(ubus_libs) $(nft_libs)"  \
 -f $(top)/Makefile dnsmasq
	for f in `cd $(PO); echo *.po`; do \
		cd $(top) && cd $(BUILDDIR) && $(MAKE) top="$(top)" -f $(top)/Makefile $${f%.po}.mo; \
	done

install-i18n : all-i18n
	$(INSTALL) -d $(DESTDIR)$(BINDIR)
	$(INSTALL) -d $(DESTDIR)$(MANDIR)/man8
	$(INSTALL) -m 644 $(MAN)/dnsmasq.8 $(DESTDIR)$(MANDIR)/man8 
	$(INSTALL) -m 755 $(BUILDDIR)/dnsmasq $(DESTDIR)$(BINDIR)
	cd $(BUILDDIR); $(top)/bld/install-mo $(DESTDIR)$(LOCALEDIR) $(INSTALL)
	cd $(MAN); ../bld/install-man $(DESTDIR)$(MANDIR) $(INSTALL)

merge : 
	@cd $(BUILDDIR) && $(MAKE) top="$(top)" -f $(top)/Makefile dnsmasq.pot
	for f in `cd $(PO); echo *.po`; do \
		echo -n msgmerge $(PO)/$$f && $(MSGMERGE) --no-wrap -U $(PO)/$$f $(BUILDDIR)/dnsmasq.pot; \
	done

# Canonicalise .po file.
%.po : 
	@cd $(BUILDDIR) && $(MAKE) -f $(top)/Makefile dnsmasq.pot
	mv $(PO)/$*.po $(PO)/$*.po.orig && $(MSGMERGE) --no-wrap $(PO)/$*.po.orig $(BUILDDIR)/dnsmasq.pot >$(PO)/$*.po; 

$(BUILDDIR):
	mkdir -p $(BUILDDIR)

# rules below are helpers for size tracking

baseline : mostly_clean all
	@cd $(BUILDDIR) && \
	   mv dnsmasq dnsmasq_baseline

bloatcheck : $(BUILDDIR)/dnsmasq_baseline mostly_clean all
	@cd $(BUILDDIR) && \
           $(top)/bld/bloat-o-meter dnsmasq_baseline dnsmasq; \
           size dnsmasq_baseline dnsmasq

# rules below are targets in recursive makes with cwd=$(BUILDDIR)

$(copts_conf): $(hdrs)
	@rm -f *.o .copts_*
	@touch $@

$(objs:.o=.c) $(hdrs):
	ln -s $(top)/$(SRC)/$@ .

$(objs): $(copts_conf) $(hdrs)

.c.o:
	$(CC) $(CFLAGS) $(COPTS) $(i18n) $(build_cflags) $(RPM_OPT_FLAGS) -c $<	

dnsmasq : $(objs)
	$(CC) $(LDFLAGS) -o $@ $(objs) $(build_libs) $(LIBS) 

dnsmasq.pot : $(objs:.o=.c) $(hdrs)
	$(XGETTEXT) -d dnsmasq --foreign-user --omit-header --keyword=_ -o $@ -i $(objs:.o=.c)

%.mo : $(top)/$(PO)/%.po dnsmasq.pot
	$(MSGMERGE) -o - $(top)/$(PO)/$*.po dnsmasq.pot | $(MSGFMT) -o $*.mo -

# Common hardening flags for production builds:
#  -D_FORTIFY_SOURCE=2  Compile-time & runtime buffer overflow detection
#  -fstack-protector-strong  Stack canaries for functions with local buffers
#  -fPIE / -pie          Position-independent executable (ASLR)
#  -Wl,-z,relro,-z,now   Full RELRO (GOT protection)
#  -pipe                  Use pipes instead of temp files (faster compilation)
#  -fno-strict-aliasing   Disable strict aliasing (safety for legacy casts)
HARDENING_CFLAGS = -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fPIE -pipe -fno-strict-aliasing
HARDENING_LDFLAGS = -pie -Wl,-z,relro,-z,now

# Build with all features enabled for Debian/Ubuntu.
# Requires: libdbus-1-dev libidn2-dev libnetfilter-conntrack-dev
#           libnftables-dev nettle-dev libgmp-dev liblua5.4-dev
debian :
	$(MAKE) \
	 COPTS="-DHAVE_DNSSEC -DHAVE_DBUS -DHAVE_LIBIDN2 -DHAVE_CONNTRACK -DHAVE_NFTSET -DHAVE_LUASCRIPT" \
	 CFLAGS="-Wall -W -O2" \
	 all-i18n

# Hardened Debian build with security flags and LTO.
# Same features as 'debian' but with stack protector, FORTIFY_SOURCE,
# PIE, RELRO, and link-time optimization for smaller/faster binary.
debian-hardened :
	$(MAKE) \
	 COPTS="-DHAVE_DNSSEC -DHAVE_DBUS -DHAVE_LIBIDN2 -DHAVE_CONNTRACK -DHAVE_NFTSET -DHAVE_LUASCRIPT" \
	 CFLAGS="-Wall -W -O2 -flto=auto $(HARDENING_CFLAGS)" \
	 LDFLAGS="-flto=auto $(HARDENING_LDFLAGS)" \
	 all-i18n

# Native-optimized build: tune for the CPU this is compiled on.
# Uses -march=native for best performance on the build machine.
# NOT portable -- the resulting binary may not run on other CPUs.
debian-native :
	$(MAKE) \
	 COPTS="-DHAVE_DNSSEC -DHAVE_DBUS -DHAVE_LIBIDN2 -DHAVE_CONNTRACK -DHAVE_NFTSET -DHAVE_LUASCRIPT" \
	 CFLAGS="-Wall -W -O2 -march=native -flto=auto $(HARDENING_CFLAGS)" \
	 LDFLAGS="-flto=auto $(HARDENING_LDFLAGS)" \
	 all-i18n

# Build with all features enabled for FreeBSD.
# Requires: dbus libidn2 nettle gmp lua54 (via pkg install)
# FreeBSD does not have conntrack, nftset, or ipset.
freebsd :
	$(MAKE) \
	 COPTS="-DHAVE_DNSSEC -DHAVE_DBUS -DHAVE_LIBIDN2 -DHAVE_LUASCRIPT -DNO_IPSET -I/usr/local/include/lua54" \
	 CFLAGS="-Wall -W -O2" \
	 LDFLAGS="-L/usr/local/lib -llua-5.4 -lintl" \
	 PREFIX="/usr/local" \
	 all

# FreeBSD build with LTO only (no hardening flags).
freebsd-lto :
	$(MAKE) \
	 COPTS="-DHAVE_DNSSEC -DHAVE_DBUS -DHAVE_LIBIDN2 -DHAVE_LUASCRIPT -DNO_IPSET -I/usr/local/include/lua54" \
	 CFLAGS="-Wall -W -O2 -flto=auto" \
	 LDFLAGS="-flto=auto -L/usr/local/lib -llua-5.4 -lintl" \
	 PREFIX="/usr/local" \
	 all

# Hardened FreeBSD build (LTO + stack protector, FORTIFY_SOURCE, PIE, RELRO).
freebsd-hardened :
	$(MAKE) \
	 COPTS="-DHAVE_DNSSEC -DHAVE_DBUS -DHAVE_LIBIDN2 -DHAVE_LUASCRIPT -DNO_IPSET -I/usr/local/include/lua54" \
	 CFLAGS="-Wall -W -O2 -flto=auto $(HARDENING_CFLAGS)" \
	 LDFLAGS="-flto=auto $(HARDENING_LDFLAGS) -L/usr/local/lib -llua-5.4 -lintl" \
	 PREFIX="/usr/local" \
	 all

help :
	@echo ""
	@echo "dnsmasq build targets:"
	@echo ""
	@echo "  Basic:"
	@echo "    all                 Build dnsmasq with default options (no external libs)"
	@echo "    all-i18n            Build with internationalisation support (requires GNU-make)"
	@echo "    install             Build and install to PREFIX (default /usr/local)"
	@echo "    install-i18n        Build and install with i18n and translated man pages"
	@echo "    clean               Remove all build artifacts"
	@echo "    mostly_clean        Remove build artifacts but keep baseline binary"
	@echo ""
	@echo "  Debian/Ubuntu:"
	@echo "    debian              All features, standard optimisation (-O2)"
	@echo "    debian-hardened     All features + FORTIFY_SOURCE, stack-protector, PIE, RELRO, LTO"
	@echo "    debian-native       Like debian-hardened + -march=native (not portable!)"
	@echo ""
	@echo "  FreeBSD:"
	@echo "    freebsd             All features (no conntrack/nftset/ipset)"
	@echo "    freebsd-lto         Like freebsd + LTO (no hardening flags)"
	@echo "    freebsd-hardened    Like freebsd + FORTIFY_SOURCE, stack-protector, PIE, RELRO, LTO"
	@echo ""
	@echo "  Development:"
	@echo "    baseline            Build and save binary as baseline for size comparison"
	@echo "    bloatcheck          Compare current build against saved baseline"
	@echo "    merge               Merge translation files"
	@echo ""
	@echo "  Hardening flags (debian-hardened, debian-native, freebsd-hardened):"
	@echo "    -D_FORTIFY_SOURCE=2      Buffer overflow detection (compile + runtime)"
	@echo "    -fstack-protector-strong  Stack canaries for vulnerable functions"
	@echo "    -fPIE / -pie             Position-independent executable (ASLR)"
	@echo "    -Wl,-z,relro,-z,now      Full RELRO (GOT write-protection)"
	@echo "    -flto=auto               Link-time optimisation (parallel)"
	@echo "    -fno-strict-aliasing     Safe legacy pointer casts"
	@echo ""
	@echo "  Custom build example:"
	@echo "    make COPTS=\"-DHAVE_DNSSEC -DHAVE_DBUS\" all-i18n"
	@echo ""
	@echo "  See src/config.h for all available COPTS (-DHAVE_xxx / -DNO_xxx)."
	@echo ""

.PHONY : all clean mostly_clean install install-common all-i18n install-i18n merge baseline bloatcheck \
	 debian debian-hardened debian-native freebsd freebsd-lto freebsd-hardened help