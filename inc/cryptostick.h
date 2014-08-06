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

int csListDevices(cs_list *cryptosticks);

//
int csGetSerialNo(card_t *card, unsigned char serialno[6]);
int csGetPublicKey(card_t *card, 
                    unsigned char** publicModulus, size_t* publicModulusLength,
                    unsigned char** publicExponent, size_t* publicExponentLength);
int csGetPublicExp(card_t *card, unsigned char** exp);

// PIN utilities
int csVerifyPIN(card_t *card, unsigned char* pin, int pinLength);
int csVerifyAdminPIN(card_t *card, unsigned char* pin, int pinLength);
int csUnblock(card_t* card, const char* new_pin, int newLength);


int csDecipher(card_t *card, unsigned char* input, size_t in_length, 
                unsigned char* output, size_t out_len);
int csEncrypt(card_t* card, unsigned char* input, unsigned inputLength,
                            unsigned char** encrypted, unsigned* encryptedLength);

int csGenerateAndImportKeyPair(card_t* card, unsigned int key_length);

int csExportKeyPairToFile(const char* file_path);

#endif // CRYPOSTICK_H

