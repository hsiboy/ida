include ../Makefile.defs

STARTFILES  = rc.idsa-full rc.idsa-simple
CONFFILES   = idsad.conf idsad-simple.conf idsad-signatures.conf idsad-interactive.conf
EDITFILES   = $(STARTFILES) $(CONFFILES) inetd.conf

DOSED       = $(SED) -e "s%/usr/local/var/log/idsa%${LOCALSTATEDIR}/log/idsa%g" \
                     -e "s%/usr/local/share/idsa%${DATADIR}/idsa%g" \
                     -e "s%/usr/local/sbin%${SBINDIR}%g" \
                     -e "s%/usr/local/etc%${SYSCONFDIR}%g"

all: $(EDITFILES)

%: %.in
	$(DOSED) $< > $@
	if [ -x $< ] ; then $(CHMOD) +x $@ ; fi

install: all
	@if [ ! -e $(SYSCONFDIR)/idsad.conf ] ; then $(INSTALL) -d $(SYSCONFDIR) ; $(INSTALL) -m 0600 idsad.conf $(SYSCONFDIR) ; $(INSTALL) -d -m 0700 $(LOCALSTATEDIR)/log/idsa; else $(WARN) "Existing $(SYSCONFDIR)/idsad.conf not modified" ; fi

info:
	@echo "Master configuration file  : $(SYSCONFDIR)/idsad.conf"
	@echo "Log file directory         : $(LOCALSTATEDIR)/log/idsa/"
	@echo "Template startup scripts   :$(foreach f,$(STARTFILES),./etc/$f)"

checkpoint: indent clean
	$(CI) -l *.in

indent:

clean: 
	$(RM) *.o *~ core $(EDITFILES)

reallyclean: clean

