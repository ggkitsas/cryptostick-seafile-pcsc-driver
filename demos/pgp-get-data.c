#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "openpgp.h"
#include "cryptostick.h"


int main()
{
    int r,i;

    apdu_t   apdu;
    card_t* card;

    // List readers
    reader_list* readerList = (reader_list*)malloc(sizeof(reader_list));
    r = pcsc_detect_readers(readerList);
    if( !r==SC_SUCCESS)
    {
        printf("%s\n",sc_strerror(r));
        return -1;
    }

    connect_card(readerList->root->reader, &card);
    card_init(card);
    
    u8  buffer[2048];
    size_t  buf_len = (card->caps & CARD_CAP_APDU_EXT)
              ? sizeof(buffer) : 256;

    pgp_get_data(card, 0xb600, buffer, buf_len);    
    return 0;
}
