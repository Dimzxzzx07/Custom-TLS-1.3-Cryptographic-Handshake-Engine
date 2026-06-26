CC      = gcc
CFLAGS  = -Wall -Wextra -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2 \
          -Icore/include -Icrypto/include -Iparser/include -Imemory/include -Iutils/include
LDFLAGS =

SOURCES = $(wildcard core/source/*.c) \
          $(wildcard crypto/source/*.c) \
          $(wildcard parser/source/*.c) \
          $(wildcard memory/source/*.c) \
          $(wildcard utils/source/*.c)
OBJECTS     = $(SOURCES:.c=.o)
TARGET      = axon-engine
STATIC_LIB  = libaxon.a
SHARED_LIB  = libaxon.so

all: $(TARGET) $(STATIC_LIB) $(SHARED_LIB)

$(TARGET): $(OBJECTS)
	$(CC) -o $@ core/source/main.c $(filter-out core/source/main.o,$(OBJECTS)) $(LDFLAGS)

$(STATIC_LIB): $(filter-out core/source/main.o,$(OBJECTS))
	ar rcs $@ $^

$(SHARED_LIB): $(filter-out core/source/main.o,$(OBJECTS))
	$(CC) -shared -fPIC -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -fPIC -c $< -o $@

test: $(STATIC_LIB)
	$(CC) $(CFLAGS) tests/c/test_handshake.c -o test_handshake $(STATIC_LIB)
	$(CC) $(CFLAGS) tests/c/test_crypto.c    -o test_crypto    $(STATIC_LIB)
	$(CC) $(CFLAGS) tests/c/test_asn1.c      -o test_asn1      $(STATIC_LIB)
	./test_handshake
	./test_crypto
	./test_asn1

clean:
	rm -f $(OBJECTS) $(TARGET) $(STATIC_LIB) $(SHARED_LIB) test_handshake test_crypto test_asn1

install: $(TARGET) $(STATIC_LIB) $(SHARED_LIB)
	install -d /usr/local/bin /usr/local/lib /usr/local/include/axon
	install -m 755 $(TARGET)      /usr/local/bin/
	install -m 644 $(STATIC_LIB)  /usr/local/lib/
	install -m 644 $(SHARED_LIB)  /usr/local/lib/
	cp -r core/include/*   /usr/local/include/axon/
	cp -r crypto/include/* /usr/local/include/axon/
	cp -r parser/include/* /usr/local/include/axon/
	cp -r memory/include/* /usr/local/include/axon/
	cp -r utils/include/*  /usr/local/include/axon/

.PHONY: all clean install test
