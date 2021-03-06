#
# doc/Makefile.  Generated from Makefile.in by configure.
#
#
# Copyright (c) 2013, Verisign, Inc., NLnet Labs
# All rights reserved.
# 
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
# * Redistributions of source code must retain the above copyright
# notice, this list of conditions and the following disclaimer.
# * Redistributions in binary form must reproduce the above copyright
#   notice, this list of conditions and the following disclaimer in the
#   documentation and/or other materials provided with the distribution.
# * Neither the names of the copyright holders nor the
#   names of its contributors may be used to endorse or promote products
#   derived from this software without specific prior written permission.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL Verisign, Inc. BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

package = getdns
version = 0.3.2
tarname = getdns
distdir = $(tarname)-$(version)

api_version = July 2015

prefix = /usr/local
exec_prefix = ${prefix}
bindir = ${exec_prefix}/bin
# datarootdir is here to please some checkers
datarootdir=${prefix}/share
mandir = ${datarootdir}/man
INSTALL = /bin/install -c

srcdir = .


EDITS=-e 's/@''version@/$(version)/g'
DOXYGEN = 

DOCDIRS = html latex man
MANPAGES3 = libgetdns.3 getdns_address.3 getdns_cancel_callback.3 getdns_context.3 getdns_context_set.3 getdns_context_set_context_update_callback.3 getdns_convert.3 getdns_dict.3 getdns_dict_get.3 getdns_dict_set.3 getdns_display_ip_address.3 getdns_general.3 getdns_hostname.3 getdns_list.3 getdns_list_get.3 getdns_list_set.3 getdns_pretty_print_dict.3 getdns_root_trust_anchor.3 getdns_service.3 getdns_validate_dnssec.3 

default: all

all: doc

doc: 	$(MANPAGES3)
	if test x_$(DOXYGEN) != x_ ; then cd ../src; doxygen; fi

.SUFFIXES: .3.in .3
.3.in.3:
	sed $(EDITS) -e "s/@date@/$(api_version)/g" $< > $@

# we assume that we want a separate file for each "name" specified for each man page
# and consider these "alternate names" simple copies of the main man page
install:	$(MANPAGES3)
	$(INSTALL) -m 755 -d $(DESTDIR)$(mandir)
	$(INSTALL) -m 755 -d $(DESTDIR)$(mandir)/man3
	for x in $(MANPAGES3); do echo $(INSTALL) -m 644 $$x $(DESTDIR)$(mandir)/man3; $(INSTALL) -m 644 $$x $(DESTDIR)$(mandir)/man3; for altpg in $$($(srcdir)/manpgaltnames $$x); do cp $$x $$altpg; echo $(INSTALL) -m 644 $$altpg $(DESTDIR)$(mandir)/man3; $(INSTALL) -m 644 $$altpg $(DESTDIR)$(mandir)/man3; done; done

check: $(MANPAGES3)
	for x in $(MANPAGES3); do LC_ALL=en_US.UTF-8 MANROFFSEQ='' MANWIDTH=80 man --warnings -E UTF-8 -l -Tutf8 -Z $$x 2>&1 >/dev/null | awk "-vpage=$$x" '{printf("%s: ", page);print}'; if ! lexgrog $$x >/dev/null 2>&1 ; then echo $$x: manpage-has-bad-whatis-entry; fi; done

uninstall:
	for x in $(MANPAGES3); do echo rm -f $(DESTDIR)$(mandir)/man3/$$x; rm -f $(DESTDIR)$(mandir)/man3/$$x; for altpg in $$($(srcdir)/manpgaltnames $$x); do echo rm -f $(DESTDIR)$(mandir)/man3/$$altpg;  rm -f $(DESTDIR)$(mandir)/man3/$$altpg; done; done

clean:
	for x in $(MANPAGES3); do rm -f $$($(srcdir)/manpgaltnames $$x); done
	rm -rf $(DOCDIRS) $(MANPAGES3)

distclean : clean
	rm -f Makefile config.status config.log
	rm -Rf autom4te.cache

Makefile: Makefile.in ../config.status
	cd .. && ./config.status $@

configure.status: configure
	cd .. && ./config.status --recheck

.PHONY: clean $(DOC)
