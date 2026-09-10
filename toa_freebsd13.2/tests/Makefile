PROG=	test_toa_core
OBJS=	test_toa_core.o toa_ut_shim.o toa_core.o

CFLAGS?=	-O2
CFLAGS+=	-std=c11 -Wall -Wextra -I.. -I.

all: $(PROG)

$(PROG): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS)

toa_core.o: ../toa_core.c ../toa_core.h
	$(CC) $(CFLAGS) -I. -c ../toa_core.c -o $@

test: $(PROG)
	./$(PROG)

clean:
	rm -f $(PROG) $(OBJS)

.PHONY: all test clean
