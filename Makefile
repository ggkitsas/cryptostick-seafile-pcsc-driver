CC=g++
CFLAGS=
LDFLAGS=-lpcsclite -lcrypto -lssl

DEMOS_DIR=$(CURDIR)/demos

LIB=-L"$(shell "pwd")/../pcsc-lite-1.8.11/build/lib" -L"/usr/lib/x86_64-linux-gnu"
INC=-I"$(shell "pwd")/../pcsc-lite-1.8.11/build/include/PCSC" -I"$(shell "pwd")/inc"

COMMON_DEPS= errors.c common.c apdu.c iso7816.c openpgp.c card.c pcsc-wrapper.c cryptostick.c

.PHONY: verify get_serial_no get_public_key decipher import_keys full_demo all

get_serial_no:
	cd src && \
	$(CC) $(CFLAGS) $(INC) $(LIB) -o get_serial_no $(COMMON_DEPS) $(DEMOS_DIR)/get_serial_no.c $(LDFLAGS) && \
	mv get_serial_no ../

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

import_keys:
	cd src && \
	$(CC) $(CFLAGS) $(INC) -I"" $(LIB) -o import_keys \
			$(COMMON_DEPS) \
			$(DEMOS_DIR)/import_keys_lib.c \
			$(DEMOS_DIR)/import_keys.c \
		    $(LDFLAGS) && \
	mv import_keys ../
	
full_demo:
	cd src && \
	$(CC) $(CFLAGS) $(INC) $(LIB) -o full_demo $(COMMON_DEPS) $(DEMOS_DIR)/full_demo.c $(LDFLAGS) && \
	mv full_demo ../
	
all: verify get_serial_no get_public_key decipher import_keys full_demo
