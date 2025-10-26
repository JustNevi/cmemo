.PHONY: build run run_test

CC = gcc
CFLAGS = -Wall -Wextra -std=c99
LDFLAGS = -lsodium

build: cmemo.c
	$(CC) $(CFLAGS) $< -o cmemo $(LDFLAGS)


run: build;
	./cmemo

run_test: build;
	valgrind ./cmemo
