#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "apdu.h"
#include "card.h"
#include "pcsc-wrapper.h"
#include "winscard.h"

int main()
{
    int r,i;

    apdu_t apdu;
/*
    card_t card;
    card.cla = 0x00;
    sc_connect_card();
    card_init(&card);
*/

    // List readers
    reader_list* readerList = (reader_list*)malloc(sizeof(reader_list));
    pcsc_detect_readers(readerList);
//    card.reader = readerList->root->reader;


    card_t* card;
    printf("%s %d\n",__FILE__, __LINE__);
    sc_connect_card(readerList->root->reader, &card);
    printf("%s %d\n",__FILE__, __LINE__);
    card_init(card);

    printf("Serial No: (len=%lu) ", card->serialnr.len);
    for(i=0;i<card->serialnr.len;i++)
        printf("%.2x ", card->serialnr.value[i]);
    printf("\n");


//    pcsc_connect(card.reader);
    pcsc_connect(card->reader);

    u8 idbuf[2];
    unsigned tag = 0xb800; // Control reference template for confidentiality (CT)
    u8 buf[256];
    size_t buf_len=256;

    // Craft apdu
//    format_apdu(&card, &apdu, APDU_CASE_4, 0x47, 0x81, 0x00);
    format_apdu(card, &apdu, APDU_CASE_4, 0x47, 0x81, 0x00);
    apdu.lc = 2;
    apdu.data = ushort2bebytes(idbuf, tag);
    apdu.datalen = 2;         
//    apdu.le = ((buf_len >= 256) && !(card.caps & CARD_CAP_APDU_EXT)) ? 256 : buf_len;
    apdu.le = ((buf_len >= 256) && !(card->caps & CARD_CAP_APDU_EXT)) ? 256 : buf_len;
    apdu.resp = buf;          
    apdu.resplen = buf_len;   

    printf("%s %d\n",__FILE__, __LINE__);
//    r = transmit_apdu(&card, &apdu);
    r = transmit_apdu(card, &apdu);
    if(r<0) {
//        pcsc_disconnect(card.reader);
        pcsc_disconnect(card->reader);
    }
    LOG_TEST_RET(r, "APDU transmit failed");                                                                                                                                                                                

//    r = check_sw(&card, apdu.sw1, apdu.sw2);
    r = check_sw(card, apdu.sw1, apdu.sw2);
    if(r<0) {
//        pcsc_disconnect(card.reader);
        pcsc_disconnect(card->reader);
    }
    LOG_TEST_RET(r, "Card returned error");                                                                                                                                                                                 


    for(i=0;i<buf_len;i++)
        printf("%.2x ",buf[i]);

//    pcsc_disconnect(card.reader);
    pcsc_disconnect(card->reader);
    LOG_FUNC_RETURN(apdu.resplen); 
    return 0;
}
