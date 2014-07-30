#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "apdu.h"
#include "card.h"
#include "pcsc-wrapper.h"
#include "winscard.h"


//#define GNUK

int main()
{
    int r,i;

    apdu_t apdu;
    // List readers
    reader_list* readerList = (reader_list*)malloc(sizeof(reader_list));
    r = pcsc_detect_readers(readerList);
    if(r != SC_SUCCESS) {
        printf("%s\n",sc_strerror(r));
        return -1;
    }

    card_t* card;
    connect_card(readerList->root->reader, &card);
    card_init(card);

    #ifndef GNUK
//    card->caps |= CARD_CAP_APDU_EXT;
    #endif

    printf("Serial No: (len=%lu) ", card->serialnr.len - 2);
    for(i=2;i<card->serialnr.len;i++)
        printf("%.2x ", card->serialnr.value[i]);
    printf("\n");

    u8 idbuf[2];
    unsigned tag = 0xb800; // Control reference template for confidentiality (CT)

    size_t buf_len=270;
    u8 buf[buf_len];

    // Craft apdu
// GNUK specific
#ifdef GNUK
    format_apdu(card, &apdu, APDU_CASE_4_SHORT, 0x47, 0x81, 0x00);
#else
    format_apdu(card, &apdu, APDU_CASE_4, 0x47, 0x81, 0x00);
#endif
    //format_apdu(card, &apdu, APDU_CASE_4, 0x47, 0x81, 0x00);
    apdu.lc = 2;
    apdu.data = ushort2bebytes(idbuf, tag);
    apdu.datalen = 2;
    apdu.le = ((buf_len >= 256) && !(card->caps & CARD_CAP_APDU_EXT)) ? 256 : buf_len;
printf("\n\n\n\n\n%d\n\n\n\n\n",apdu.le);
    apdu.resp = buf;          
    apdu.resplen = buf_len;   

printf("------------------------------------------------------------------------- START ---------------------------------------------------\n");
    r = transmit_apdu(card, &apdu);
    LOG_TEST_RET(r, "APDU transmit failed");                                                                                                                                                                                

    r = check_sw(card, apdu.sw1, apdu.sw2);
    LOG_TEST_RET(r, "Card returned error");                                                                                                                                                                                 


    for(i=0;i<buf_len;i++)
        printf("%.2x ",buf[i]);

    LOG_FUNC_RETURN(apdu.resplen); 
    return 0;
}
