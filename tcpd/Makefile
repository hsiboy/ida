include ../Makefile.defs

WRAPPERSRC = idsatcpd.c
WRAPPER    = idsatcpd


LD_LIBRARY_PATH = ../lib
INCLUDE         = -I../include -I../common
LIB             = -L../lib -L../common -lidsa -lidsacommon

ifneq ($(GNUNET),no)
all: $(WRAPPER)
install: all
	@$(INSTALL) -m 0755 $(WRAPPER) $(SBINDIR)
info:
else
all:
install:
info:
endif

%: %.c ../include/*.h ../common/*.h
	$(CC) $(CFLAGS) -DVERSION=\"$(VERSION)\" $(INCLUDE) $(COMMON) $< -o $@ $(LIB)

checkpoint: indent clean
	$(CI) -l *.c

indent:
	$(INDENT) *.c

clean: 
	$(RM) *.o *~ core

reallyclean: clean
	$(RM) $(WRAPPER)
