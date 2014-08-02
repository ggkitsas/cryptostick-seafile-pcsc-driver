#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "card.h"
#include "pcsc-wrapper.h"
#include "openpgp.h"
#include "cryptostick.h"

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

    r = csVerifyAdminPIN(card, (unsigned char*)"12345678", 8);
    if (r!=SC_SUCCESS)
        printf("Admin verification failed\n");

    return 0;
}
