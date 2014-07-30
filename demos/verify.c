#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "card.h"
#include "pcsc-wrapper.h"
#include "openpgp.h"

unsigned char *getline(size_t size) {
    if (size <= 0) size = 1;
    unsigned char *str;
    int ch;
    size_t len = 0;
    str = (unsigned char*)realloc(NULL, sizeof(char)*size); //size is start size
    if (!str) return str;
    while ((ch = getchar()) && ch != '\n') {
        str[len++] = ch;
        if(len == size){
            str = (unsigned char*)realloc(str, sizeof(char)*(size*=2));
            if (!str) return str;
        }
    }
    str[len++]='\0';

    return (unsigned char*)realloc(str, sizeof(char)*len);
}

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

    // Initialize pin data
    sc_pin_cmd_data pin_data;
    pin_data.cmd = SC_PIN_CMD_VERIFY;
    pin_data.pin_reference = 2;
//    pin_data.pin1.data = (const u8*)"123456" ;
//    pin_data.pin1.len = 6;

    printf("Please provide user PIN:\n");
    unsigned char* pin = getline(6);
    printf("PIN: %s\n",pin);

    pin_data.pin1.data = (const u8*)pin;
    pin_data.pin1.len = strlen((const char*)pin);
    pin_data.pin1.min_length = 6;
    pin_data.pin1.max_length = 32;
    pin_data.pin1.encoding = SC_PIN_ENCODING_ASCII;
    
    int tries_left=3;
    printf("%s %d\n",__FILE__,__LINE__);
    pgp_pin_cmd(card, &pin_data, &tries_left);
    
}

