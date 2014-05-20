include ../Makefile.defs

EXAMPLESRC = simple-example.c
EXAMPLE    = simple-example

LD_LIBRARY_PATH = ../lib
INCLUDE = -I../include
LIB     = -L../lib -lidsa

all: $(EXAMPLE)

install:

%: %.c ../include/*.h
	$(CC) $(CFLAGS) -DVERSION=\"$(VERSION)\" $(INCLUDE) $(COMMON) $< -o $@ $(LIB)

info: 
	@echo "Sample code                :./example/simple-example.c"

checkpoint: indent clean
	$(CI) -l *.c

indent:
	$(INDENT) *.c

clean: 
	$(RM) *.o *~ core

reallyclean: clean
	$(RM) $(EXAMPLE)
