#ifndef CRYPOSTICK_H
#define CRYPOSTICK_H

#include "common.h"
#include "pcsc-wrapper.h"
#include "card.h"

typedef struct _cs_list_node {
    card_t* card;
    struct _cs_list_node* next;
} cs_list_node;

typedef struct cs_list {
    cs_list_node* root;
    size_t numOfNodes;
} cs_list;

int csListDevices(cs_list &cryptosticks);
int csGetSerialNo(card_t *card, unsigned char serialno[6]);
int csGetPublicKey(card_t *card, unsigned char* public_key);
int csVerifyPIN(card_t *card, unsigned char* pin);
int csDecipher(card_t *card, unsigned char* input, size_t in_length, 
                unsigned char* output, size_t out_len);


#endif // CRYPOSTICK_H

