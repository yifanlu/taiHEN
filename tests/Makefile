CC=gcc
LD=gcc
CFLAGS=-g
INCS=-Iinclude
LIBS=-lpthread

.PHONY: all clean

all: test_proc_map test_patches

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS) $(INCS)

%.to: ../%.c
	$(CC) -c -o $@ $< $(CFLAGS) $(INCS)

test_proc_map: compat.o test_proc_map.o proc_map.to
	$(LD) -o $@ $^ $(CFLAGS) $(LIBS)

test_patches: compat.o test_patches.o patches.to proc_map.to
	$(LD) -o $@ $^ $(CFLAGS) $(LIBS)

clean:
	rm -f *.o *~ test_proc_map test_patches