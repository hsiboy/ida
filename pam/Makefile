include ../Makefile.defs

PAMSRC = pam_idsa.c
PAMSO  = pam_idsa.so
PAMO   = pam_idsa.o

CFLAGS += -fPIC
LDFLAGS = -shared

INCLUDE = -I../include
LIB     = -L../lib -lidsa -lpam

ifneq ($(PAMDIR),no)
all: $(PAMSO)
install: all
	@$(INSTALL) -m 644 $(PAMSO) $(PAMDIR)
info:
	@echo "PAM Activation             : call $(PAMSO) from the files in /etc/pam.d"
else 
all:
install:
info:
endif

$(PAMSO): $(PAMO)
	$(CC) -shared -Wl,-x $(PAMO) -o $(PAMSO) $(LIB)

%.o: %.c
	$(CC) $(CFLAGS) -DVERSION=\"$(VERSION)\" $(INCLUDE) -c $< -o $@

checkpoint: indent clean
	$(CI) -l *.[ch]

indent:
	$(INDENT) $(PAMSRC)

clean:
	$(RM) *.o *~ core

reallyclean: clean
	$(RM) $(PAMSO)
