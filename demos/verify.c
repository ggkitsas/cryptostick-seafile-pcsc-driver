#include <stdio.h>
#include <stdlib.h>

#include "common.h"
#include "card.h"
#include "pcsc-wrapper.h"
#include "openpgp.h"

int main()
{
    int r,i;

/*    
    card_t card;
    card_init(&card);
*/
    reader_list* readerList = (reader_list*)malloc(sizeof(reader_list));
    pcsc_detect_readers(readerList);

    card_t* card;
    connect_card(readerList->root->reader, &card);
    card_init(card);

    printf("Serial No: (len=%lu) ", card->serialnr.len);
    for(i=0;i<card->serialnr.len;i++)
        printf("%.2x ", card->serialnr.value[i]);
    printf("\n");

    if(r<0)
        printf("Error returned by pcsc_detect_readers\n");

    printf("%s %d\n",__FILE__,__LINE__);
//    card.reader = readerList->root->reader;

//    pcsc_connect(card.reader);
    pcsc_connect(card->reader);
    printf("%s %d\n",__FILE__,__LINE__);

    sc_pin_cmd_data pin_data;
/*
    unsigned int cmd;         
    unsigned int flags;
    unsigned int pin_type;      /* usually SC_AC_CHV */
/*    int pin_reference;
    struct sc_pin_cmd_pin pin1, pin2;
    apdu_t *apdu; 
*/

    pin_data.cmd = SC_PIN_CMD_VERIFY;
//    pin_data.flags = ;
    pin_data.pin_reference = 2;

////    const char *prompt; /* Prompt to display */
//    const u8 *data;     /* PIN, if given by the appliction */
//    int len;        /* set to -1 to get pin from pin pad */
//    size_t min_length;  /* min/max length of PIN */
//    size_t max_length;        
//    unsigned int encoding;  /* ASCII-numeric, BCD, etc */  
//    size_t pad_length;  /* filled in by the card driver */
//    u8 pad_char;
//    size_t offset;      /* PIN offset in the APDU */   
////    size_t length_offset;   /* Effective PIN length offset in the APDU */
////    int max_tries;  /* Used for signaling back from SC_PIN_CMD_GET_INFO */
////    int tries_left; /* Used for signaling back from SC_PIN_CMD_GET_INFO */

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

