#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

#include "cryptostick.h"

int csListDevices(cs_list &cryptosticks)
{
    int r;

    reader_list* readerList = (reader_list*)malloc(sizeof(reader_list));

    r = pcsc_detect_readers(readerList);
    if ( ! r == SC_SUCCESS) {
        free(readerList);
        return r;
    }

    
    int i;
    cryptosticks.numOfNodes = 0;
    cs_list_node* csCurrentNode;
    cs_list_node* previousNode;
    reader_list_node* readerCurrentNode = readerList->root;

    for( i=0; i<readerList->readerNum; i++)
    {   
        csCurrentNode = (cs_list_node*)malloc(sizeof(cs_list_node));
        r = connect_card(readerCurrentNode->reader, &(csCurrentNode->card));
        if(! r == SC_SUCCESS)
            continue;

        r = card_init(csCurrentNode->card);
        if(! r == SC_SUCCESS)
            continue;

        if(i == 0) {
            cryptosticks.root = csCurrentNode;
            previousNode = cryptosticks.root;
        } else {
            previousNode->next = csCurrentNode;
            previousNode = previousNode->next;
        }
        cryptosticks.numOfNodes++;
      

        if(i != cryptosticks.numOfNodes -1) {
            readerCurrentNode = readerCurrentNode->next;
        }
    }

    return SC_SUCCESS;
}

int csGetSerialNo(card_t *card, unsigned char serialno[6])
{
    int r;
    memcpy(serialno, &(card->serialnr.value[2]), 6);
    return 0;
}

int csGetPublicKey(card_t *card, unsigned char* public_key)
{
    int r;

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

    r = pcsc_connect(card->reader);
    if (r == SC_ERROR_CARD_REMOVED)
        r = pcsc_reconnect(card->reader, SCARD_UNPOWER_CARD);
    if (! r == SC_SUCCESS)
        return -1;

    pcsc_disconnect(card->reader);
    return 0;
}

int csDecipher(card_t *card, unsigned char* input, size_t in_len,
                unsigned char* output, size_t out_len)
{
    int r;

    r = pcsc_connect(card->reader);
//    if (! r == SC_SUCCESS)
//        return -1;

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
