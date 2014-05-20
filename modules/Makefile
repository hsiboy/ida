include ../Makefile.defs

#CFLAGS += -DDEBUG

MODULES = $(foreach m,$(SHAREDMODULES),mod_$(m).so)

CFLAGS += -fPIC
LDFLAGS = -shared -Wl,-x

INCLUDE = -I../include
LIB     = -L../lib -lidsa

ifneq ($(DLDIR),no)
all: $(MODULES)
install: all
	@$(INSTALL) -m 755 -d $(DLDIR)
	@$(INSTALL) -m 755 $(MODULES) $(DLDIR)
info:
else
all:
install:
info:
endif

# special case needs math library 
mod_sad.so: mod_sad.o
	$(CC) $(LDFLAGS) $< -o $@ $(LIB) -lm

%.so: %.o
	$(CC) $(LDFLAGS) $< -o $@ $(LIB)

%.o: %.c ../Makefile.defs
	$(CC) $(CFLAGS) -DVERSION=\"$(VERSION)\" $(INCLUDE) -c $< -o $@

checkpoint: indent clean
	$(CI) -l *.[ch]

indent:
	$(INDENT) *.c

clean:
	$(RM) *.o *~ core

reallyclean: clean
	$(RM) $(MODULES)
