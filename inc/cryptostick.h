#ifndef CRYPOSTICK_H
#define CRYPOSTICK_H

#include "common.h"
#include "pcsc-wrapper.h"
#include "card.h"

int csListDevices(reader_list* readerList);
int csGetPublicKey(card_t *card, unsigned char* public_key);
int csGetPublicKey(card_t *card, unsigned char* public_key);
int csVerifyPIN(card_t *card, unsigned char* pin);
int csDecipher(card_t *card, unsigned char* input, size_t in_length, 
                unsigned char* output, size_t out_len);


#endif // CRYPOSTICK_H

