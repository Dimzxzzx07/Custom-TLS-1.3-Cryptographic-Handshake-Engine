CC      = gcc
CFLAGS  = -Wall -Wextra -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2 \
          -Icore/include -Icrypto/include -Iparser/include -Imemory/include -Iutils/include -fPIC
LDFLAGS =

SOURCES = $(wildcard core/source/*.c) \
          $(wildcard crypto/source/*.c) \
          $(wildcard parser/source/*.c) \
          $(wildcard memory/source/*.c) \
          $(wildcard utils/source/*.c)
OBJECTS     = $(SOURCES:.c=.o)
STATIC_LIB  = libaxon.a
SHARED_LIB  = libaxon.so

all: $(STATIC_LIB) $(SHARED_LIB)

$(STATIC_LIB): $(OBJECTS)
	ar rcs $@ $^

$(SHARED_LIB): $(OBJECTS)
	$(CC) -shared -fPIC -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

test: $(STATIC_LIB)
	$(CC) $(CFLAGS) tests/c/test_handshake.c -o test_handshake $(STATIC_LIB)
	$(CC) $(CFLAGS) tests/c/test_crypto.c    -o test_crypto    $(STATIC_LIB)
	$(CC) $(CFLAGS) tests/c/test_asn1.c      -o test_asn1      $(STATIC_LIB)
	./test_handshake && ./test_crypto && ./test_asn1

clean:
	rm -f $(OBJECTS) $(STATIC_LIB) $(SHARED_LIB) test_handshake test_crypto test_asn1

install: $(STATIC_LIB) $(SHARED_LIB)
	install -d $(DESTDIR)/usr/lib $(DESTDIR)/usr/include/axon
	install -m 644 $(STATIC_LIB)  $(DESTDIR)/usr/lib/
	install -m 644 $(SHARED_LIB)  $(DESTDIR)/usr/lib/
	cp core/include/*.h    $(DESTDIR)/usr/include/axon/
	cp crypto/include/*.h  $(DESTDIR)/usr/include/axon/
	cp parser/include/*.h  $(DESTDIR)/usr/include/axon/
	cp memory/include/*.h  $(DESTDIR)/usr/include/axon/
	cp utils/include/*.h   $(DESTDIR)/usr/include/axon/

.PHONY: all clean install test
