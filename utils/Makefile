include ../Makefile.defs

#CFLAGS += -DTRACE

SRC     = idsaexec.c idsapid.c idsapipe.c idsalog.c idsasocket.c idsascaffold.c idsaxmlheader.sh

SBIN_UTILS = idsaexec  idsapid    idsapipe
BIN_UTILS  = idsalog   idsasocket idsascaffold idsaxmlheader

LD_LIBRARY_PATH = ../lib
INCLUDE = -I../include -I../common
LIB     = -L../lib -L../common -lidsa -lidsacommon

all: $(BIN_UTILS) $(SBIN_UTILS)

install: all
	@$(INSTALL) -d $(SBINDIR)
	@$(INSTALL) -m 0755 $(SBIN_UTILS) $(SBINDIR)
	@$(INSTALL) -d $(BINDIR)
	@$(INSTALL) -m 0755 $(BIN_UTILS)  $(BINDIR)

info:

%: %.c ../include/*.h ../common/*.h
	$(CC) $(CFLAGS) -DVERSION=\"$(VERSION)\" $(INCLUDE) $(COMMON) $< -o $@ $(LIB)

%: %.sh
	$(CP) $< $@ 
	$(CHMOD) 755 $@

checkpoint: indent clean
	$(CI) -l *.c

indent:
	$(INDENT) *.c

clean: 
	$(RM) *.o *~ core

reallyclean: clean
	$(RM) $(SBIN_UTILS) $(BIN_UTILS)
