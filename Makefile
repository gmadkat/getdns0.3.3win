#
# Makefile.  Generated from Makefile.in by configure.
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
version = 0.3.2rc1
tarname	= getdns
PACKAGE_TARNAME	= getdns
distdir	= $(tarname)-$(version)
bintar  = $(distdir)-bin.tar.gz

prefix = /usr/local
datarootdir=${prefix}/share
exec_prefix = ${prefix}
bindir = ${exec_prefix}/bin
docdir = ${datarootdir}/doc/${PACKAGE_TARNAME}

srcdir = .
INSTALL = /bin/install -c

all : default 

default:
	cd src && $(MAKE) $@

install: all 
	$(INSTALL) -m 755 -d $(DESTDIR)$(docdir)
	$(INSTALL) -m 644 $(srcdir)/AUTHORS $(DESTDIR)$(docdir)
	$(INSTALL) -m 644 $(srcdir)/ChangeLog $(DESTDIR)$(docdir)
	$(INSTALL) -m 644 $(srcdir)/COPYING $(DESTDIR)$(docdir)
	$(INSTALL) -m 644 $(srcdir)/INSTALL $(DESTDIR)$(docdir)
	$(INSTALL) -m 644 $(srcdir)/LICENSE $(DESTDIR)$(docdir)
	$(INSTALL) -m 644 $(srcdir)/NEWS $(DESTDIR)$(docdir)
	$(INSTALL) -m 644 $(srcdir)/README.md $(DESTDIR)$(docdir)
	$(INSTALL) -m 755 -d $(DESTDIR)$(docdir)/spec
	$(INSTALL) -m 644 $(srcdir)/spec/index.html $(DESTDIR)$(docdir)/spec
	$(INSTALL) -m 644 $(srcdir)/spec/getdns*tgz $(DESTDIR)$(docdir)/spec
	cd src && $(MAKE) $@
	cd doc && $(MAKE) $@
	@echo "***"
	@echo "***  !!! IMPORTANT !!!!  libgetdns needs a DNSSEC trust anchor!"
	@echo "***"
	@echo "***  For the library to be able to perform DNSSEC, the root"
	@echo "***  trust anchor needs to be present in presentation format"
	@echo "***  in the file: "
	@echo "***        /etc/unbound/getdns-root.key"
	@echo "***"
	@echo "***  We recomend using unbound-anchor to retrieve and install"
	@echo "***  the root trust anchor like this: "
	@echo "***        mkdir -p `dirname /etc/unbound/getdns-root.key`"
	@echo "***        unbound-anchor -a \"/etc/unbound/getdns-root.key\""
	@echo "***"
	@echo "***  We strongly recommend package maintainers to provide the"
	@echo "***  root trust anchor by installing it with unbound-anchor"
	@echo "***  at package installation time from the post-install script."
	@echo "***"

uninstall: 
	rm -rf $(DESTDIR)$(docdir)
	cd doc && $(MAKE) $@
	cd src && $(MAKE) $@

doc:	FORCE
	cd doc && $(MAKE) $@

example:
	cd spec/example && $(MAKE) $@

test:
	cd src && $(MAKE) $@

getdns_query:
	cd src && $(MAKE) $@

install-getdns_query:
	cd src/test && $(MAKE) install

uninstall-getdns_query:
	cd src/test && $(MAKE) uninstall

clean:
	cd src && $(MAKE) $@
	cd doc && $(MAKE) $@
	cd spec/example && $(MAKE) $@
	rm -f *.o

depend:
	cd src && $(MAKE) $@

distclean:
	cd src && $(MAKE) $@
	rmdir src 2>/dev/null || true
	cd doc && $(MAKE) $@
	rmdir doc 2>/dev/null || true
	cd spec/example && $(MAKE) $@
	rmdir spec/example 2>/dev/null || true
	rmdir spec 2>/dev/null || true
	rm -f config.log config.status Makefile libtool
	rm -fR autom4te.cache
	rm -f m4/libtool.m4
	rm -f m4/lt~obsolete.m4
	rm -f m4/ltoptions.m4
	rm -f m4/ltsugar.m4
	rm -f m4/ltversion.m4
	rm -f $(distdir).tar.gz $(distdir).tar.gz.sha1
	rm -f $(distdir).tar.gz.md5 $(distdir).tar.gz.asc

megaclean:
	cd $(srcdir) && rm -fr * .dir-locals.el .gitignore .indent.pro .travis.yml && git reset --hard

dist: $(distdir).tar.gz

pub: $(distdir).tar.gz.sha1 $(distdir).tar.gz.md5 $(distdir).tar.gz.asc

$(distdir).tar.gz.sha1: $(distdir).tar.gz
	openssl sha1 $(distdir).tar.gz >$@

$(distdir).tar.gz.md5: $(distdir).tar.gz
	openssl md5 $(distdir).tar.gz >$@

$(distdir).tar.gz.asc: $(distdir).tar.gz
	gpg --armor --detach-sig $(distdir).tar.gz

bindist: $(bintar)

$(bintar): $(distdir)
	chown -R 0:0 $(distdir) 2>/dev/null || true
	cd $(distdir); ./configure; make
	tar chof - $(distdir) | gzip -9 -c > $@
	rm -rf $(distdir)

$(distdir).tar.gz: $(distdir)
	chown -R 0:0 $(distdir) 2>/dev/null || true
	tar chof - $(distdir) | gzip -9 -c > $@
	rm -rf $(distdir)

$(distdir):
	mkdir -p $(distdir)/m4
	mkdir -p $(distdir)/src
	mkdir -p $(distdir)/src/getdns
	mkdir -p $(distdir)/src/test
	mkdir -p $(distdir)/src/extension
	mkdir -p $(distdir)/src/compat
	mkdir -p $(distdir)/src/util
	mkdir -p $(distdir)/src/gldns
	mkdir -p $(distdir)/doc
	mkdir -p $(distdir)/spec
	mkdir -p $(distdir)/spec/example
	cp $(srcdir)/configure.ac $(distdir)
	cp $(srcdir)/configure $(distdir)
	cp $(srcdir)/AUTHORS $(distdir)
	cp $(srcdir)/ChangeLog $(distdir)
	cp $(srcdir)/COPYING $(distdir)
	cp $(srcdir)/INSTALL $(distdir)
	cp $(srcdir)/LICENSE $(distdir)
	cp $(srcdir)/NEWS $(distdir)
	cp $(srcdir)/README.md $(distdir)
	cp $(srcdir)/Makefile.in $(distdir)
	cp $(srcdir)/install-sh $(distdir)
	cp $(srcdir)/config.sub $(distdir)
	cp $(srcdir)/config.guess $(distdir)
	cp libtool $(distdir)
	cp $(srcdir)/ltmain.sh $(distdir)
	cp $(srcdir)/m4/*.m4 $(distdir)/m4
	cp $(srcdir)/src/*.in $(distdir)/src
	cp $(srcdir)/src/*.[ch] $(distdir)/src
	cp $(srcdir)/src/*.symbols $(distdir)/src
	cp $(srcdir)/src/extension/*.[ch] $(distdir)/src/extension
	cp $(srcdir)/src/extension/*.symbols $(distdir)/src/extension
	cp $(srcdir)/src/getdns/*.in $(distdir)/src/getdns
	cp $(srcdir)/src/getdns/getdns_*.h $(distdir)/src/getdns
	cp $(srcdir)/src/test/Makefile.in $(distdir)/src/test
	cp $(srcdir)/src/test/*.[ch] $(distdir)/src/test
	cp $(srcdir)/src/test/*.sh $(distdir)/src/test
	cp $(srcdir)/src/test/*.good $(distdir)/src/test
	cp $(srcdir)/src/compat/*.[ch] $(distdir)/src/compat
	cp $(srcdir)/src/util/*.[ch] $(distdir)/src/util
	cp $(srcdir)/src/gldns/*.[ch] $(distdir)/src/gldns
	cp $(srcdir)/doc/Makefile.in $(distdir)/doc
	cp $(srcdir)/doc/*.in $(distdir)/doc
	cp $(srcdir)/doc/manpgaltnames $(distdir)/doc
	cp $(srcdir)/spec/*.html $(distdir)/spec
	cp $(srcdir)/spec/*.tgz $(distdir)/spec
	cp $(srcdir)/spec/example/Makefile.in $(distdir)/spec/example
	cp $(srcdir)/spec/example/*.[ch] $(distdir)/spec/example
	rm -f $(distdir)/Makefile $(distdir)/src/Makefile $(distdir)/src/getdns/getdns.h $(distdir)/spec/example/Makefile $(distdir)/src/test/Makefile $(distdir)/doc/Makefile $(distdir)/src/config.h

distcheck: $(distdir).tar.gz
	gzip -cd $(distdir).tar.gz | tar xvf -
	cd $(distdir) && ./configure
	cd $(distdir) && $(MAKE) all
	cd $(distdir) && $(MAKE) check
	cd $(distdir) && $(MAKE) DESTDIR=$${PWD}/_inst install
	cd $(distdir) && $(MAKE) DESTDIR=$${PWD}/_inst uninstall
	@remaining="`find $${PWD}/$(distdir)/_inst -type f | wc -l`"; \
	if test "$${remaining}" -ne	0; then
	echo "@@@	$${remaining} file(s) remaining	in stage directory!"; \
	exit 1; \
	fi
	cd $(distdir) && $(MAKE) clean
	rm -rf $(distdir)
	@echo "*** Package $(distdir).tar.gz is ready for distribution"

Makefile: $(srcdir)/Makefile.in config.status
	./config.status $@

configure.status: configure
	./config.status --recheck

.PHONY: all distclean clean default doc test
FORCE:
