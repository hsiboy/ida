include ../Makefile.defs

SERVERSRC = io.c idsad.c job.c set.c messages.c
SERVEROBJ = io.o idsad.o job.o set.o messages.o

SERVER    = $(PROJECT)d

INCLUDE = -I../include -I../common
LIB     = -L../lib -L../common -lidsa -lidsacommon

all: $(SERVER)

install: all
	@$(INSTALL) -d $(SBINDIR)
	@$(INSTALL) -m 755 $(SERVER) $(SBINDIR)

info:

$(SERVER): $(SERVEROBJ)
	$(CC) $(CFLAGS) $(SERVEROBJ) -o $(SERVER) $(LIB)

%.o: %.c *.h ../include/*.h ../common/*.h
	$(CC) $(CFLAGS) -DVERSION=\"$(VERSION)\" $(INCLUDE) -c $< -o $@

checkpoint: indent clean
	$(CI) -l *.[ch]

indent:
	$(INDENT) $(SERVERSRC)

clean:
	$(RM) *.o *~ core *.log

reallyclean: clean
	$(RM) $(SERVER)
