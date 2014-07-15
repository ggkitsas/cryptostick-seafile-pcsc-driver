#include <stdlib.h>
#include <string.h>
#include "common.h"

#include "cryptostick.h"

int csListDevices(reader_list* readerList)
{
    int r;

    readerList = (reader_list*)malloc(sizeof(reader_list));
    r = pcsc_detect_readers(readerList);
    if ( ! r == SC_SUCCESS) {
        free(readerList);
        return r;
    }

    return SC_SUCCESS;
}

int cardInit(card_t *card)
{
    card_init(card);
    return 0;
}

int csGetSerialNo(card_t *card, unsigned char serialno[6])
{
    int r;

    connect_card(card->reader, &card);
    memcpy(serialno, &(card->serialnr.value[2]), 6);
    pcsc_disconnect(card->reader);
    return 0;
}

int csGetPublicKey(card_t *card, unsigned char* public_key)
{
    int r;

    connect_card(card->reader, &card);
    
    pcsc_disconnect(card->reader);
    return 0;
}

int csVerifyPIN(card_t *card, unsigned char* pin)
{
    int r;

    connect_card(card->reader, &card);

    pcsc_disconnect(card->reader);
    return 0;
}

int csDecipher(card_t *card, unsigned char* input, size_t in_length, 
                unsigned char* output, size_t out_len)
{
    int r;

    connect_card(card->reader, &card);

    pcsc_disconnect(card->reader);
    return 0;
}
