#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cryptostick.h"

int main()
{
    int r;
    card_t* card;
    reader_list* readerList = (reader_list*)malloc(sizeof(reader_list));
    r = pcsc_detect_readers(readerList);
    if( !r==SC_SUCCESS)
    {
        printf("pcsc_detect_readers: %s\n",sc_strerror(r));
        return -1;
    }

    connect_card(readerList->root->reader, &card);
    card_init(card);

    csVerifyAdminPIN(card, (unsigned char*)"12345678", 8);

    csGenerateAndImportKeyPair(card, 2048);
    csExportKeyPairToFile("~/");

    return 0;
}
