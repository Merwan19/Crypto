CC=	gcc
CFLAGS=	-g
LIB=	-lmd -lssl -lcrypto

proc: proc.o proc.c proc.h
	gcc -o proc $(CFLAGS) proc.o $(LIB)

clean:
	rm -rf *.o
