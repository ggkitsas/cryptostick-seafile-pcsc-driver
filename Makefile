CC=g++
CFLAGS=
LDFLAGS=-lpcsclite #-lssl

DEMOS_DIR=$(CURDIR)/demos

LIB=-L"$(shell "pwd")/../pcsc-lite-1.8.11/build/lib"
INC=-I"$(shell "pwd")/../pcsc-lite-1.8.11/build/include/PCSC" -I"$(shell "pwd")/inc"

COMMON_DEPS= errors.c common.c apdu.c iso7816.c openpgp.c card.c pcsc-wrapper.c

.PHONY: verify get_public_key decipher all


get_public_key:
	cd src && \
	$(CC) $(CFLAGS) $(INC) $(LIB) -o get_public_key $(COMMON_DEPS) $(DEMOS_DIR)/get_public_key.c $(LDFLAGS) && \
	mv get_public_key ../

decipher:
	cd src && \
	$(CC) $(CFLAGS) $(INC) $(LIB) -o decipher $(COMMON_DEPS) $(DEMOS_DIR)/decipher.c $(LDFLAGS) && \
	mv decipher ../

verify:	
	cd src && \
	$(CC) $(CFLAGS) $(INC) $(LIB) -o verify $(COMMON_DEPS) $(DEMOS_DIR)/verify.c $(LDFLAGS) && \
	mv verify ../

all: verify get_public_key decipher
