
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "card.h"
#include "pcsc-wrapper.h"


int main()
{
    int r;

    apdu_t   apdu;
    card_t card;
    card.cla=0x00;

    card_init(&card);
    // List readers
    reader_list* readerList = (reader_list*)malloc(sizeof(reader_list));
    r = pcsc_detect_readers(readerList);
    if( !r==SC_SUCCESS)
    {
        printf("%s\n",sc_strerror(r));
        return -1;
    }

    card.reader = readerList->root->reader;

    pcsc_connect(card.reader);

    u8 *in = (u8*)"blabla";
    u8 out[6];
    size_t inlen=6, outlen=6;

//    struct pgp_priv_data *priv = DRVDATA(&card);
    u8 *temp = NULL;

    /* There's some funny padding indicator that must be
     * prepended... hmm. */
    if (!(temp = (u8*)malloc(inlen + 1)))
        return SC_ERROR_OUT_OF_MEMORY;
    temp[0] = '\0';
    memcpy(temp + 1, in, inlen);   
    in = temp;
    inlen += 1;

    // Craft apdu
    format_apdu(&card, &apdu, APDU_CASE_4, 0x2A, 0x80, 0x86);
    apdu.lc = inlen;
    apdu.data = in;
    apdu.datalen = inlen;
    apdu.le = ((outlen >= 256) && !(card.caps & CARD_CAP_APDU_EXT)) ? 256 : outlen;
    apdu.resp = out;
    apdu.resplen = outlen;

    r = transmit_apdu(&card, &apdu); 
    free(temp);
    if(r<0)
        pcsc_disconnect(card.reader);
        
    LOG_TEST_RET(r, "APDU transmit failed\n");

    r = check_sw(&card, apdu.sw1, apdu.sw2);
    if(r<0)
        pcsc_disconnect(card.reader);

    pcsc_disconnect(card.reader);
    LOG_TEST_RET(r, "Card returned error\n");
}

