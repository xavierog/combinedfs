# Not exactly an advanceed Makefile...

PREFIX = /usr/local

all:

install: combinedfs.py
	install -C combinedfs.py "$(PREFIX)/sbin/combinedfs"
