.PHONY: build run run_test

CC = gcc
CFLAGS = -Wall -Wextra -std=c99
LDFLAGS = -lsodium

build: cmemo.c
	$(CC) $(CFLAGS) $< -o cmemo.o $(LDFLAGS)


run: build;
	./cmemo.o

run_test: build;
	valgrind ./cmemo.o
