#include <stdio.h>
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

    
    int i;
    sc_reader_t* tmp_reader;
    tmp_reader = readerList->root->reader;
    for(i=0;i<readerList->readerNum;i++)
    {
        connect_card(tmp_reader, &card);
        card_init(card);
    }
    return SC_SUCCESS;
}

int csGetSerialNo(card_t *card, unsigned char serialno[6])
{
    int r;

    connect_card(card->reader, &card);
    pcsc_connect(card->reader);

    memcpy(serialno, &(card->serialnr.value[2]), 6);

    pcsc_disconnect(card->reader);
    return 0;
}

int csGetPublicKey(card_t *card, unsigned char* public_key)
{
    int r;

    connect_card(card->reader, &card);
    pcsc_connect(card->reader);
    
    apdu_t apdu;

    u8 idbuf[2];
    unsigned tag = 0xb800; // Control reference template for confidentiality (CT)
    u8 buf[256];
    size_t buf_len=256;

    format_apdu(card, &apdu, APDU_CASE_4, 0x47, 0x81, 0x00);
    apdu.lc = 2;
    apdu.data = ushort2bebytes(idbuf, tag);
    apdu.datalen = 2;         
    apdu.le = ((buf_len >= 256) && !(card->caps & CARD_CAP_APDU_EXT)) ? 256 : buf_len;
    apdu.resp = buf;          
    apdu.resplen = buf_len;   


    r = transmit_apdu(card, &apdu);
    if(r<0) {
        pcsc_disconnect(card->reader);
    }
    LOG_TEST_RET(r, "APDU transmit failed");

    r = check_sw(card, apdu.sw1, apdu.sw2);
    if(r<0) {
        pcsc_disconnect(card->reader);
    }
    LOG_TEST_RET(r, "Card returned error");

    pcsc_disconnect(card->reader);

    public_key = (unsigned char*)malloc(sizeof(unsigned char)*buf_len);
    memcpy(public_key, buf, buf_len);
    
    return 0;
}

int csVerifyPIN(card_t *card, unsigned char* pin)
{
    int r;

    connect_card(card->reader, &card);
    pcsc_connect(card->reader);

    pcsc_disconnect(card->reader);
    return 0;
}

int csDecipher(card_t *card, unsigned char* input, size_t in_len,
                unsigned char* output, size_t out_len)
{
    int r;

    connect_card(card->reader, &card);
    pcsc_connect(card->reader);

    u8 *temp = NULL;
    apdu_t   apdu;
    /* There's some funny padding indicator that must be
     * prepended... hmm. */
    if (!(temp = (u8*)malloc(in_len + 1)))
        return SC_ERROR_OUT_OF_MEMORY;
    temp[0] = '\0';
    memcpy(temp + 1, input, in_len);   
    input = temp;
    in_len += 1;

    // Craft apdu
    format_apdu(card, &apdu, APDU_CASE_4, 0x2A, 0x80, 0x86);
    apdu.lc = in_len;
    apdu.data = input;
    apdu.datalen = in_len;
    apdu.le = ((out_len >= 256) && !(card->caps & CARD_CAP_APDU_EXT)) ? 256 : out_len;
    apdu.resp = output;
    apdu.resplen = out_len;

    r = transmit_apdu(card, &apdu); 
    free(temp);
    if(r<0)
        pcsc_disconnect(card->reader);
    LOG_TEST_RET(r, "APDU transmit failed\n");

    r = check_sw(card, apdu.sw1, apdu.sw2);
    if(r<0)
        pcsc_disconnect(card->reader);

    pcsc_disconnect(card->reader);

    LOG_TEST_RET(r, "Card returned error\n");
}
