VERSION=1.1

DESTDIR ?=
PREFIX ?= /usr/local
PKG_CONFIG ?= pkg-config
DIAL_CFLAGS = $(shell $(PKG_CONFIG) --cflags libevent)
DIAL_LIBS = $(shell $(PKG_CONFIG) --libs libevent)

udpbroadcastrelay: main.c dial-ipv6.c dial-ipv6.h dial-clat.c dial-clat.h
	$(CC) $(CPPFLAGS) $(CFLAGS) $(DIAL_CFLAGS) -g main.c dial-ipv6.c dial-clat.c -o udpbroadcastrelay $(LDFLAGS) $(DIAL_LIBS)

clean:
	rm -f udpbroadcastrelay tests/test-dial-clat

tests/test-dial-clat: tests/test-dial-clat.c dial-clat.c dial-clat.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -Wall -Wextra -Werror -I. tests/test-dial-clat.c dial-clat.c -o $@ $(LDFLAGS)

check: tests/test-dial-clat
	./tests/test-dial-clat

all: udpbroadcastrelay

install:
	install -pm0755 udpbroadcastrelay $(DESTDIR)$(PREFIX)/sbin/
