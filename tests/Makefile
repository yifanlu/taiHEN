CC=gcc
LD=gcc
CFLAGS=
INCS=-Iinclude
LIBS=-lpthread

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

%.to: ../%.c
	$(CC) -c -o $@ $< $(CFLAGS)

test_proc_map: compat.o test_proc_map.o proc_map.to
	$(LD) -o $@ $^ $(CFLAGS) $(LIBS)

.PHONY: all clean

all: test_proc_map

clean:
	rm -f *.o *~ test_proc_map