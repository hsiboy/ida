include ../Makefile.defs

DOCS = BLURB CREDITS INSTALL TODO WARNING
MAN1 = idsa.1 idsalog.1 
MAN3 = idsa_close.3 idsa_open.3 idsa_scan.3 idsa_set.3 idsa_types.3
MAN5 = idsad.conf.5
MAN7 = idsa-scheme-am.7 idsa-scheme-clf.7 idsa-scheme-err.7 \
       idsa-scheme-ldm.7 idsa-scheme-ssm.7 idsa-scheme-fnl.7 \
       idsa-scheme-rq.7
MAN8 = idsad.8 idsatcplogd.8 idsatcpd.8 idsaklogd.8 \
       idsasyslogd.8 idsarlogd.8 idsapid.8 \
       idsapipe.8 idsaexec.8 idsaguardtty.8 \
       mod_chain.8 mod_constrain.8 mod_counter.8 \
       mod_exists.8 mod_interactive.8 mod_keep.8 \
       mod_length.8 mod_log.8 mod_regex.8 \
       mod_send.8 mod_time.8 mod_timer.8 \
       mod_true.8 mod_truncated.8 mod_type.8

ifneq ($(GUILECONFIG),no)
MAN8 += idsaguile.8
endif

ifneq ($(GTKCONFIG),no)
MAN8 += idsaguardgtk.8
endif

all: 

install: 
	@$(INSTALL) -d $(foreach m,1 3 5 7 8,$(MANDIR)/man$(m))
	@$(INSTALL) -m 644 $(MAN1) $(MANDIR)/man1
	@$(INSTALL) -m 644 $(MAN3) $(MANDIR)/man3
	@$(INSTALL) -m 644 $(MAN5) $(MANDIR)/man5
	@$(INSTALL) -m 644 $(MAN7) $(MANDIR)/man7
	@$(INSTALL) -m 644 $(MAN8) $(MANDIR)/man8

info:
	@echo "Overview                   : man 1 idsa"
	@echo "Configuration help         : man 5 idsad.conf"
	@echo "Invocation help            : man 8 idsad"
	@echo "API documentation          : man 3 idsa_open idsa_set idsa_close"


checkpoint: indent clean
	$(CI) -l $(DOCS) $(MAN1) $(MAN3) $(MAN5) $(MAN7) $(MAN8) 

indent:

clean: 
	$(RM) *.o *~ core *.bak

reallyclean: clean
