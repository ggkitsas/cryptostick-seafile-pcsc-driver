CC=g++
CFLAGS=
LDFLAGS=-lpcsclite #-lssl

#PKG_CONFIG_PATH=/home/cyc0/Projects/smartcards/pcsc-lite-1.8.11/build/lib/pkgconfig

LIB=-L"/home/cyc0/Projects/smartcards/pcsc-lite-1.8.11/build/lib"
INC=-I"/home/cyc0/Projects/smartcards/pcsc-lite-1.8.11/build/include/PCSC" -I"$(shell "pwd")"

#asn1.c
COMMON_DEPS= errors.c common.c apdu.c iso7816.c openpgp.c card.c pcsc-wrapper.c

.PHONY: verify get_public_key decipher all

get_public_key:
	$(CC) $(CFLAGS) $(INC) $(LIB) -o get_public_key $(COMMON_DEPS) get_public_key.c $(LDFLAGS)

decipher:
	$(CC) $(CFLAGS) $(INC) $(LIB) -o decipher $(COMMON_DEPS) decipher.c $(LDFLAGS)

verify:
	$(CC) $(CFLAGS) $(INC) $(LIB) -o verify $(COMMON_DEPS) verify.c $(LDFLAGS)

all: verify get_public_key decipher
