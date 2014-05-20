include Makefile.defs

DIRECTORIES  = include/ lib/ common/ server/ utils/ doc/ syslog/ tcpd/ tcplogd/ guile/ pam/ snoopy/ example/ tools/ modules/ apache/ guard/ etc/
PACKAGEFILES = $(DIRECTORIES) README Makefile configure *.in
ARCHIVE      = $(PROJECT)-$(VERSION).tar.gz

build: all
help: info

distclean: reallyclean
	$(RM) config.cache config.status config.log

all checkpoint indent clean reallyclean install info : 
	for d in $(DIRECTORIES); do if ! $(MAKE) -C $$d $@; then exit; fi; done

package: indent distclean
	$(AUTOCONF)
	$(RM) $(PROJECT)-$(VERSION) $(ARCHIVE)
	$(LN) . $(PROJECT)-$(VERSION)
	$(TAR) czhlvf $(ARCHIVE) $(foreach f,$(PACKAGEFILES),$(PROJECT)-$(VERSION)/$(f))
	$(RM) $(PROJECT)-$(VERSION)
