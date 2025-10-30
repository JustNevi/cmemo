CC = gcc
CFLAGS = -Wall -Wextra -std=c99
LDFLAGS = -lsodium

EXE = cmemo 

SRCS = cmemo.c
OBJS = $(SRCS:.c=.o)

all: $(EXE)

$(EXE): $(OBJS)
	$(CC) $(OBJS) $(LDFLAGS) -o $@

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(EXE)

.PHONY: all clean
