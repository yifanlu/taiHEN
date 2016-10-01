CC=gcc
CFLAGS=-I.
LIBS=-lpthread

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

test_proc_map: compat.o test_proc_map.o
	$(LD) -o $@ $^ $(CFLAGS) $(LIBS)

.PHONY: all clean

all: test_proc_map

clean:
	rm -f *.o *~ test_proc_map