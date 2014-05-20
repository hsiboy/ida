include ../Makefile.defs

MODSRC = mod_idsa.c
MODSO  = mod_idsa.so
MODO   = mod_idsa.o

INCLUDE = -I ../include 
LIB     = -L ../lib -lidsa
LDFLAGS = -shared -Wl,-x

CFLAGS  += -fPIC

# check if APXS is set in Makefile.defs
ifneq ($(APXS),no)

INCLUDE += -I $(shell $(APXS) -q INCLUDEDIR)
CFLAGS  += $(shell $(APXS) -q CFLAGS)
CFLAGS  += $(shell $(APXS) -q CFLAGS_SHLIB)

all: $(MODSO)
install: all
	$(APXS) -i -a $(MODSO)
info:
	@echo "Apache 1.3 activation      : append 'IdsaLog On' to httpd.conf and restart httpd"
else
all:
install:
info:
endif

%.so: %.o
	$(CC) $(LDFLAGS) $< -o $@ $(LIB)

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDE) -c $< -o $@

checkpoint: indent clean
	$(CI) -l *.[ch]

indent:
	$(INDENT) $(MODSRC)

clean:
	$(RM) *.o *~ core

reallyclean: clean
	$(RM) $(MODSO)

