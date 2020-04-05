# Not exactly an advanceed Makefile...

PREFIX = /usr/local
CC = gcc

all:

readdir: readdir.c
	$(CC) readdir.c -o readdir

install: combinedfs.py
	install -C combinedfs.py "$(PREFIX)/sbin/combinedfs"
