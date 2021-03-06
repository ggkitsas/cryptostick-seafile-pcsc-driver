CC=g++
CFLAGS=
LDFLAGS=-lpcsclite -lcrypto -lssl

DEMOS_DIR=$(CURDIR)/demos

LIB=-L"/usr/lib/x86_64-linux-gnu"
INC=-I/usr/include/PCSC/ -I"$(shell "pwd")/inc"

COMMON_DEPS= errors.c common.c apdu.c iso7816.c openpgp.c card.c pcsc-wrapper.c cryptostick.c

.PHONY: openssl_evp verify get_serial_no get_public_key decipher import_keys openpgp-file export_keypair unblock full_demo all

openssl_evp:
	cd src && \
	$(CC) $(CFLAGS) $(INC) $(LIB) -o openssl_evp $(DEMOS_DIR)/openssl_evp.c $(LDFLAGS) && \
	mv openssl_evp ../

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

verify_admin:
	cd src && \
	$(CC) $(CFLAGS) $(INC) $(LIB) -o verify_admin $(COMMON_DEPS) $(DEMOS_DIR)/verify_admin.c $(LDFLAGS) && \
	mv verify_admin ../

import_keys:
	cd src && \
	$(CC) $(CFLAGS) $(INC) -I"" $(LIB) -o import_keys \
			$(COMMON_DEPS) \
			$(DEMOS_DIR)/import_keys.c \
		    $(LDFLAGS) && \
	mv import_keys ../

openpgp-file:
	cd src && \
	$(CC) $(CFLAGS) $(INC) -I"" $(LIB) -o openpgp-file \
			$(COMMON_DEPS) \
			openpgp-msg.c \
			$(DEMOS_DIR)/openpgp-file.c \
		    $(LDFLAGS) && \
	mv openpgp-file ../

export_keypair:	
	cd src && \
	$(CC) $(CFLAGS) $(INC) $(LIB) -o export_keypair $(COMMON_DEPS) $(DEMOS_DIR)/export_keypair.c $(LDFLAGS) && \
	mv export_keypair ../

unblock:	
	cd src && \
	$(CC) $(CFLAGS) $(INC) $(LIB) -o unblock $(COMMON_DEPS) $(DEMOS_DIR)/unblock.c $(LDFLAGS) && \
	mv unblock ../

get_pin_counter:
	cd src && \
	$(CC) $(CFLAGS) $(INC) $(LIB) -o get-pin-counter $(COMMON_DEPS) $(DEMOS_DIR)/get-pin-counter.c $(LDFLAGS) && \
	mv get-pin-counter ../

full_demo:
	cd src && \
	$(CC) $(CFLAGS) $(INC) $(LIB) -o full_demo $(COMMON_DEPS) $(DEMOS_DIR)/full_demo.c $(LDFLAGS) && \
	mv full_demo ../
	
all: openssl_evp verify get_serial_no get_public_key decipher import_keys openpgp-file export_keypair unblock full_demo
