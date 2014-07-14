CC=g++
CFLAGS=
LDFLAGS=-lpcsclite #-lssl

DEMOS_DIR=$(CURDIR)/demos
#PKG_CONFIG_PATH=/home/cyc0/Projects/smartcards/pcsc-lite-1.8.11/build/lib/pkgconfig

LIB=-L"$(shell "pwd")/../pcsc-lite-1.8.11/build/lib"
INC=-I"$(shell "pwd")/../pcsc-lite-1.8.11/build/include/PCSC" -I"$(shell "pwd")"

#asn1.c
COMMON_DEPS= errors.c common.c apdu.c iso7816.c openpgp.c card.c pcsc-wrapper.c

.PHONY: verify get_public_key decipher all


get_public_key:
	$(CC) $(CFLAGS) $(INC) $(LIB) -o get_public_key $(COMMON_DEPS) $(DEMOS_DIR)/get_public_key.c $(LDFLAGS)

decipher:
	$(CC) $(CFLAGS) $(INC) $(LIB) -o decipher $(COMMON_DEPS) $(DEMOS_DIR)/decipher.c $(LDFLAGS)

verify:	
	$(CC) $(CFLAGS) $(INC) $(LIB) -o verify $(COMMON_DEPS) $(DEMOS_DIR)/verify.c $(LDFLAGS)

all: verify get_public_key decipher
