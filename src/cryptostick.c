#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include "openpgp.h"

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

int csGetPublicKey(card_t *card, unsigned char** public_key)
{
    int r;

//    pcsc_connect(card->reader);
    
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
/*    if(r<0) {
        pcsc_disconnect(card->reader);
    }
*/
    LOG_TEST_RET(r, "APDU transmit failed");

    r = check_sw(card, apdu.sw1, apdu.sw2);
/*    if(r<0) {
        pcsc_disconnect(card->reader);
    }
*/

    LOG_TEST_RET(r, "Card returned error");

//    pcsc_disconnect(card->reader);

    *public_key = (unsigned char*)malloc(sizeof(unsigned char)*buf_len);
    memcpy(*public_key, buf, buf_len);
 
    return 0;
}

int csGetPublicExp(card_t *card, unsigned char** exp)
{
    int r;

//    pcsc_connect(card->reader);
    
    apdu_t apdu;

    u8 idbuf[2];
    unsigned tag = 0xb800; // Control reference template for confidentiality (CT)
    u8 buf[256];
    size_t buf_len=4;

    format_apdu(card, &apdu, APDU_CASE_4, 0x47, 0x82, 0x00);
    apdu.lc = 2;
    apdu.data = ushort2bebytes(idbuf, tag);
    apdu.datalen = 2;         
    apdu.le = ((buf_len >= 256) && !(card->caps & CARD_CAP_APDU_EXT)) ? 256 : buf_len;
    apdu.resp = buf;          
    apdu.resplen = buf_len;   


    r = transmit_apdu(card, &apdu);
    LOG_TEST_RET(r, "APDU transmit failed");

    r = check_sw(card, apdu.sw1, apdu.sw2);
    LOG_TEST_RET(r, "Card returned error");


    *exp = (unsigned char*)malloc(sizeof(unsigned char)*buf_len);
    memcpy(*exp, buf, buf_len);
 
    return 0;
}

int csVerifyPIN(card_t *card, unsigned char* pin, int pinLength)
{
    int r;

    sc_pin_cmd_data pin_data;
    pin_data.cmd = SC_PIN_CMD_VERIFY;
    pin_data.pin_reference = 2;

    pin_data.pin1.data = (const u8*)pin ;
    pin_data.pin1.len = pinLength;
    pin_data.pin1.min_length = 6;
    pin_data.pin1.max_length = 32;
    pin_data.pin1.encoding = SC_PIN_ENCODING_ASCII;

    int tries_left;
    pgp_pin_cmd(card, &pin_data, &tries_left);

    return 0;
}

int csDecipher(card_t *card, unsigned char* input, size_t in_len,
                unsigned char* output, size_t out_len)
{
    int r;

//    r = pcsc_connect(card->reader);
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
/*    if(r<0)
        pcsc_disconnect(card->reader);
*/
    LOG_TEST_RET(r, "APDU transmit failed\n");

    r = check_sw(card, apdu.sw1, apdu.sw2);
/*    if(r<0)
        pcsc_disconnect(card->reader);
*/

//    pcsc_disconnect(card->reader);
    LOG_TEST_RET(r, "Card returned error\n");
}
