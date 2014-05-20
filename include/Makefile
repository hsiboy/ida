include ../Makefile.defs

INCLUDES = idsa.h idsa_internal.h idsa_schemes.h

all:

install:
	@$(INSTALL) -d $(INCLUDEDIR)
	@$(INSTALL) -m 0644 $(INCLUDES) $(INCLUDEDIR)

info:

checkpoint: indent clean
	$(CI) -l $(INCLUDES)

indent:
	$(INDENT) $(INCLUDES)

clean: 
	$(RM) *~ core

reallyclean: clean
