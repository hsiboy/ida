include ../Makefile.defs

CFLAGS  += -DVERSION=\"$(VERSION)\"
#CFLAGS += -DTRACE
#CFLAGS += -ggdb

LIB      = -L../lib -lidsa
INCLUDE  = -I../include

GUARDTTY = idsaguardtty
GUARDGTK = idsaguardgtk


TARGET  += idsaguardtty

ifneq ($(STANDOUT),no)
TTYEXTRA = -DSTANDOUT -l$(STANDOUT)
endif

ifneq ($(GTKCONFIG),no)
TARGET  += idsaguardgtk
GTKEXTRA = $(shell $(GTKCONFIG) --cflags ; $(GTKCONFIG) --libs)
endif


all: $(TARGET)

install: all
	@$(INSTALL) -d $(BINDIR)
	@$(INSTALL) -m 0755 $(TARGET) $(BINDIR)

info:

$(GUARDTTY): $(GUARDTTY).c
	$(CC) $(CFLAGS) $(INCLUDE) $< -o $@ $(LIB) $(TTYEXTRA)

$(GUARDGTK): $(GUARDGTK).c
	$(CC) $(CFLAGS) $(INCLUDE) $< -o $@ $(LIB) $(GTKEXTRA)


checkpoint: indent clean
	$(CI) -l *.c

indent:
	$(INDENT) *.c

clean: 
	$(RM) *.o *~ core

reallyclean: clean
	$(RM) $(TARGET)
