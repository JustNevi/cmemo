CC = gcc
CFLAGS = -Wall -Wextra -std=c99
LDFLAGS = -lsodium

PREFIX = /usr/local

EXE = cmemo 

SRCS = cmemo.c
OBJS = $(SRCS:.c=.o)

all: $(EXE)

$(EXE): $(OBJS)
	$(CC) $(OBJS) $(LDFLAGS) -o $@

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

install: all
	install -m 755 $(EXE) $(PREFIX)/bin

uninstall:
	rm -f $(PREFIX)/bin/$(EXE)

clean:
	rm -f $(OBJS) $(EXE)

.PHONY: all clean
