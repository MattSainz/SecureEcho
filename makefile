CC=gcc
CFLAGS=-I.
LDFLAGS= -L/usr/local/lib
LDLIBS= -lcrypto -lssl
OBJ= src/echoServer.o 
OBJ_C= src/echoClient.o

all: echoServer echoClient

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

echoServer: $(OBJ)
	gcc -o $@ $^ $(CFLAGS) $(LDLIBS)

echoClient: $(OBJ_C)
	gcc -o $@ $^ $(CFLAGS) $(LDLIBS)

.PHONY: clean

clean:
	rm -f echoServer echoClient src/echoServer.o src/echoClient.o

