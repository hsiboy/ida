include ../Makefile.defs

GUILESRC = guile.c
GUILEOBJ = guile.o

IDSAGUILE     = $(PROJECT)guile

INCLUDE = -I../include -I../common
LIB     = -L../lib -L../common -lidsacommon -lidsa

ifneq ($(GUILECONFIG),no)
all: $(IDSAGUILE)
install: all
	@$(INSTALL) -m 755 $(IDSAGUILE) $(SBINDIR)
	@$(INSTALL) -m 755 -d $(DATADIR)/idsa
	@$(INSTALL) -m 644 *.scm $(DATADIR)/idsa
info:
else
all:
install:
info:
endif

ifneq ($(GUILECONFIG),no)
$(IDSAGUILE): $(GUILEOBJ)
	$(CC) $(CFLAGS) $(GUILEOBJ) -o $(IDSAGUILE) $(LIB) $(shell $(GUILECONFIG) link)

%.o: %.c ../include/*.h ../common/*.h
	$(CC) $(CFLAGS) -DVERSION=\"$(VERSION)\" $(INCLUDE) -c $< -o $@ $(shell $(GUILECONFIG) compile)
endif

checkpoint: indent clean
	$(CI) -l *.[ch] *.scm

indent:
	$(INDENT) $(GUILESRC)

clean:
	$(RM) *.o *~ core

reallyclean: clean
	$(RM) $(IDSAGUILE)
