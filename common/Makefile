include ../Makefile.defs

COMMONLIB = libidsacommon.a
COMMONOBJ = misc.o udomain.o scheme.o socketlock.o sparse.o
COMMONSRC = misc.c udomain.c scheme.c socketlock.c sparse.c

all: $(COMMONLIB)

install: all

$(COMMONLIB): $(COMMONOBJ)
	$(AR) rcs $(COMMONLIB) $(COMMONOBJ)
	$(RANLIB) $(COMMONLIB)

%.o: %.c *.h ../include/*.h
	$(CC) $(CFLAGS) $(CDEFS) -I../include -c $< -o $@

info:

checkpoint: indent clean
	$(CI) -l *.[ch]

indent:
	$(INDENT) *.c

clean: 
	$(RM) *.o *~ core

reallyclean: clean
	$(RM) $(COMMONLIB)
