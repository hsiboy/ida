include ../Makefile.defs

SYSLOG    = idsasyslogd idsarlogd
ifneq ($(KLOG),no)
SYSLOG   += idsaklogd
endif

#CFLAGS   += -DTRACE

LD_LIBRARY_PATH = ../lib
INCLUDE         = -I../include -I../common
LIB             = -L../lib -L../common -lidsa -lidsacommon

all: $(SYSLOG)

install: all
	@$(INSTALL) -m 0755 $(SYSLOG) $(SBINDIR)

info:

%: %.c ../include/*.h ../common/*.h
	$(CC) $(CFLAGS) -DVERSION=\"$(VERSION)\" $(INCLUDE) $(COMMON) $< -o $@ $(LIB)

checkpoint: indent clean
	$(CI) -l *.c

indent:
	$(INDENT) *.c

clean: 
	$(RM) *.o *~ core

reallyclean: clean
	$(RM) $(SYSLOG)
