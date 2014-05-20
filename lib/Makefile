include ../Makefile.defs 

CFLAGS += -fPIC
#CFLAGS += -DDEBUG

MAJOR        = 2
MINOR        = 4.0

ifneq ($(DLDIR),no)
  CFLAGS    += -DDLDIR=\"$(DLDIR)\"
  LIB        = $(DLLIB)
endif

ifneq ($(FALLBACK),no)
  CFLAGS    += -DFALLBACK
endif

VPATH        = ../modules
LIBOBJ       = client.o event.o unit.o types.o protocol.o \
               wire.o risk.o print.o syslog.o escape.o mex.o \
               rule.o module.o parse.o error.o support.o version.o \
               $(foreach m,$(STATICMODULES),mod_$(m).o)

LIBLITE      = lib$(PROJECT)lite.so.$(MAJOR)
LIBNAME      = lib$(PROJECT).so
LIBNAMEMAJOR = $(LIBNAME).$(MAJOR)
LIBNAMEMINOR = $(LIBNAME).$(MAJOR).$(MINOR)
LDSOCONF     = /etc/ld.so.conf

INCLUDE      = -I../include

all: $(LIBNAMEMINOR)

info: 
	@if [ ! -f $(LIBDIR)/$(LIBNAMEMINOR) ] ; then \
          echo "Core library               : not installed" ; \
	elif [ $(LIBNAMEMINOR) -nt $(LIBDIR)/$(LIBNAMEMINOR) ] ; then \
	  echo "Core library               : old version installed" ; \
	else \
	  echo "Core library               : $(LIBDIR)/$(LIBNAMEMINOR)" ; \
	  if ! $(GREP) -q $(LIBDIR) $(LDSOCONF) ; then \
          @$(WARN) "You may have to add $(LIBDIR) to $(LDSOCONF) and run $(LDCONFIG)" ; \
	  fi ; \
	fi

install: all
	@$(INSTALL) -d -m 0755 $(LIBDIR)
	@$(INSTALL) -m 0755 $(LIBNAMEMINOR) $(LIBDIR)
	-$(RM) $(LIBDIR)/$(LIBNAMEMAJOR) $(LIBDIR)/$(LIBNAME)
	(cd $(LIBDIR) ; $(LN) $(LIBNAMEMINOR) $(LIBNAMEMAJOR))
	(cd $(LIBDIR) ; $(LN) $(LIBNAMEMINOR) $(LIBNAME))
ifeq ($(shell test -f $(LIBDIR)/$(LIBLITE) && echo yes),yes)
	@$(WARN) "Existing $(LIBDIR)/$(LIBLITE) not modified" 
else
	(cd $(LIBDIR) ; $(LN) $(LIBNAMEMINOR) $(LIBLITE)) 
endif
	$(LDCONFIG)

$(LIBNAMEMINOR): $(LIBOBJ)
	$(RM) $(LIBNAME) $(LIBNAMEMAJOR)
	$(CC) -shared -Wl,-x,-soname,$(LIBNAMEMAJOR) $(LIBOBJ) -o $(LIBNAMEMINOR) $(LIB)
	$(LN) $(LIBNAMEMINOR) $(LIBNAMEMAJOR)
	$(LN) $(LIBNAMEMINOR) $(LIBNAME)

# cosmetic, could be done at top
module.o: module.c ../include/*.h ../Makefile.defs
	$(CC) $(CFLAGS) $(INCLUDE) -DFIXEDMODULES="$(foreach m,$(STATICMODULES),idsa_module_load_$(m),) NULL" -DVERSION=\"$(VERSION)\" -c $< -o $@

%.o: %.c ../include/*.h ../Makefile.defs
	$(CC) $(CFLAGS) $(INCLUDE) -DVERSION=\"$(VERSION)\" -c $< -o $@

checkpoint: indent clean
	$(CI) -l *.[ch]

indent:
	$(INDENT) *.c

clean:
	$(RM) *.o *~ core

reallyclean: clean
	$(RM) libidsa*so*

