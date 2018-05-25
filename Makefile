
OBJS=tweetnacl.o saltcrypt.o randombytes.o kdf.o
CFLAGS=-Wall -O2 


saltcrypt:  $(OBJS)
	$(CC) $(OBJS) -o saltcrypt $(LDFLAGS)

clean:
	rm -rf *.o *.S saltcrypt
