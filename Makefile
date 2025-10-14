.PHONY: build run

CC = gcc
CFLAGS = -Wall -Wextra -std=c99
LDFLAGS = -lsodium

build: main.c
	$(CC) $(CFLAGS) $< -o main.o $(LDFLAGS)


run: build;
	./main.o

run_test: build;
	valgrind ./main.o
