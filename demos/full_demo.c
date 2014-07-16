#include <stdio.h>
#include "cryptostick.h"
#include "pcsc-wrapper.h"

int main()
{
    int i,j;

    cs_list csList;
    csListDevices(csList);

//    pcsc_connect(csList.root->card->reader);
    unsigned char pubkey[256];
    csGetPublicKey(csList.root->card, pubkey);
    printf("Public key: %s\n\n\n",pubkey);

    // Get serial number
    unsigned char serialNo[6];
    for(i=0; i<csList.numOfNodes; i++) {
        csGetSerialNo(csList.root->card, serialNo);
        printf("serialno: %s\n",serialNo);   
            for(j=2;j<6;j++) {
                printf("%.2x ",csList.root->card->serialnr.value[j]);
            }
        printf("\nReader name: %s\n", csList.root->card->reader->name);
    }


    unsigned char plain[6];
    unsigned char* ciph = (unsigned char*)"abcabc";
    csDecipher(csList.root->card, ciph, 6, plain, 6);

    // pcsc_disconnect(csList.root->card->reader);
    return 0;
}
