#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "apdu.h"
#include "card.h"
#include "pcsc-wrapper.h"
#include "winscard.h"
#include "cryptostick.h"

#define GNUK

int main()
{
    int r,i,j;

    cs_list cryptosticks;
    if( csListDevices(&cryptosticks) == 0 ) { 
        cs_list_node* currentNode = cryptosticks.root;

        for(int i=0; i<cryptosticks.numOfNodes; i++) {
            unsigned char* serialNo = (unsigned char*)malloc(sizeof(unsigned char)*6);
            csGetSerialNo(currentNode->card, serialNo);

            printf("Serial No (card %d): (len=%lu) ", 
                    i, currentNode->card->serialnr.len - 2);
            for(j=2; j<currentNode->card->serialnr.len ;j++)
                printf("%.2x ", currentNode->card->serialnr.value[j]);
            printf("\n");

            free(serialNo);
            if(i!=cryptosticks.numOfNodes-1)
                currentNode = currentNode->next;
        }
    }
}
