include ../Makefile.defs

SNOOPYSRC = snoopy.c
SNOOPYSO  = snoopy.so

INCLUDE = -I../include
LIB     = -L../lib -lidsa $(DLLIB)
CFLAGS += -fPIC

all: $(SNOOPYSO)

install: all
	@$(INSTALL) -m 755 $(SNOOPYSO) $(LIBDIR)

info:

$(SNOOPYSO): $(SNOOPYSRC)
	$(CC) $(CFLAGS) -shared $(SNOOPYSRC) $(LIB) $(INCLUDE) -o $(SNOOPYSO)

checkpoint: indent clean
	$(CI) -l *.[ch]

indent:
	$(INDENT) $(SNOOPYSRC)

clean:
	$(RM) *.o *~ core

reallyclean: clean
	$(RM) $(SNOOPYSO)
