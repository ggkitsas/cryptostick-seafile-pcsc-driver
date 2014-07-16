#include <stdio.h>
#include <stdlib.h>

#include "common.h"
#include "card.h"
#include "pcsc-wrapper.h"
#include "openpgp.h"

int main()
{
    int r,i;

    reader_list* readerList = (reader_list*)malloc(sizeof(reader_list));
    r = pcsc_detect_readers(readerList);
    if(!r == SC_SUCCESS) {
        printf("%s\n", sc_strerror(r));
        return -1;
    }

    card_t* card;
    connect_card(readerList->root->reader, &card);
    card_init(card);

    printf("Serial No: (len=%lu) ", card->serialnr.len-2);
    for(i=2;i<card->serialnr.len;i++)
        printf("%.2x ", card->serialnr.value[i]);
    printf("\n");

    if(r<0)
        printf("Error returned by pcsc_detect_readers\n");

    printf("%s %d\n",__FILE__,__LINE__);

//    pcsc_connect(card.reader);
    pcsc_connect(card->reader);
    printf("%s %d\n",__FILE__,__LINE__);

    sc_pin_cmd_data pin_data;

    pin_data.cmd = SC_PIN_CMD_VERIFY;
    pin_data.pin_reference = 2;

    struct sc_acl_entry acls[SC_MAX_SDO_ACLS];

    pin_data.pin1.data = (const u8*)"123456" ;
    pin_data.pin1.len = 6;
    pin_data.pin1.min_length = 6;
    pin_data.pin1.max_length = 32;
    pin_data.pin1.encoding = SC_PIN_ENCODING_ASCII;
    
    int tries_left;
printf("%s %d\n",__FILE__,__LINE__);
//    pgp_pin_cmd(&card, &pin_data, &tries_left);
    pgp_pin_cmd(card, &pin_data, &tries_left);
    
}

