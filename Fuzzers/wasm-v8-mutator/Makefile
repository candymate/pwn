all: libmutator.so test

libmutator.so:
	$(CC) $(CFLAGS) -D_FORTIFY_SOURCE=2 -O3 -fPIC -shared -g -I ../../AFLplusplus/include mutator.c -o libmutator.so

test:
	$(CC) $(CFLAGS) test.c -o test -L. -lmutator

clean:
	rm -f libmutator.so test
