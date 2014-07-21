#include <stdio.h>
#include "cryptostick.h"
#include "pcsc-wrapper.h"

int main()
{
    int i,j,r;

    cs_list csList;
    csListDevices(csList);

    card_t *card = csList.root->card;

    // Get public key
/*    unsigned char pubkey[256];
    csGetPublicKey(card, pubkey);
    printf("Public key: %s\n\n\n",pubkey);
*/
    // Get serial number
    unsigned char serialNo[6];
    for(i=0; i<csList.numOfNodes; i++) {
        csGetSerialNo(card, serialNo);
        printf("serialno: %s\n",serialNo);   
            for(j=2;j<6;j++) {
                printf("%.2x ",csList.root->card->serialnr.value[j]);
            }
        printf("\nReader name: %s\n", csList.root->card->reader->name);
    }

    // Host encryption
    unsigned char* encrypted;
    unsigned encryptedLength;
    unsigned char* input = (unsigned char*)"blablo";
    r = csEncrypt(card,input , 6, &encrypted, &encryptedLength);
    printf("Encrypted outside: ");
    for(i=0;i<encryptedLength;i++)
        printf("%.2x ",encrypted[i]);
    printf("\n\n\n\n\n\n");

    if(r!=0){
        printf("Encrypt error\n");
        return -1;
    }
    printf("EncLength= %d\n",encryptedLength);

    // PIN
    unsigned char* pin = (unsigned char*)"123456";
    csVerifyPIN(card, pin, 6);

    // Card decryption
    unsigned char plain[6];
    csDecipher(card, encrypted, encryptedLength, plain, 6);

    printf("%s\n", plain);

    return 0;
}
