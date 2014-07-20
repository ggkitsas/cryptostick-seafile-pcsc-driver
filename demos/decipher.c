
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "openssl/rsa.h"
#include "openssl/bio.h"
#include "openssl/pem.h"

#include "common.h"
#include "card.h"
#include "openpgp.h"
#include "pcsc-wrapper.h"
#include "iso7816.h"
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

// PIN verification
    r = csVerifyPIN(card, (unsigned char*)"123456", 6);
    LOG_TEST_RET(r, "PIN verification failed");    

// Get public key
    unsigned char* publicKey;//[256];
    r = csGetPublicKey(card, &publicKey);
    LOG_TEST_RET(r, "Fetching public key failed");


// Get public exponent
/*    unsigned char* exp;//[4];
    r = csGetPublicExp(card, &exp);
    printf("EXponent: ");
    for(i=0;i<4;i++)
        printf("%.2x ",exp[i]);
    printf("\n");
*/

// ENCRYPT
printf("-------------------------- Encrypting ------------------------------------\n");

    RSA* rsa = NULL;
    unsigned char encrypted[4098] = {};
    const char* e = "65537";

    unsigned char publicKeyHex[256*2+1];
    
    unsigned char* hex_map = (unsigned char*)"0123456789abcdef";
    for(i=0;i<256;i++)
    {
        publicKeyHex[i*2] = hex_map[ publicKey[i] >> 4 ];
        publicKeyHex[i*2+1] = hex_map[ publicKey[i] & 0x0f ];
    }
    publicKeyHex[i]='\0';
    printf("%s\n", publicKeyHex);

    rsa = RSA_new();

    if(!BN_hex2bn(&rsa->n, (const char*)publicKeyHex)) {
        printf("modulo parsing error\n");
    }

    if (!BN_dec2bn(&rsa->e, e)) {
        printf("exponent parsing error");
    }

/*
    BIO *keybio;
    keybio = BIO_new_mem_buf(publicKey, -1);
printf("BIO_new_mem_buf\n");
//    rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
    rsa = d2i_RSAPublicKey(NULL, (const unsigned char**)&publicKey, 2096);
printf("d2i_RSAPublicKey\n");
*/

    int enc_length = RSA_public_encrypt(6, (unsigned char*)"blabla", encrypted, rsa, RSA_PKCS1_PADDING);
    if(enc_length == -1) {
        printf("Public key encrypt failed\n");
//        return -1;
    }else {
        printf("\n\n\n Encrypted: (len=%d) \n",enc_length);
    }
    for(i=0;i<enc_length;i++)
        printf("%.2x ",encrypted[i]);
    printf("\n\n\n");


// DECIPHER
    // u8 *in = (u8*)"blabla";
    u8 *in = (u8*)encrypted;
    u8 out[6];
    size_t inlen=256;//enc_length;
    size_t outlen=6;


r = iso7816_decipher(card,
        in, inlen,
        out, outlen);
LOG_TEST_RET(r, "Card returned error\n");

/*
//    struct pgp_priv_data *priv = DRVDATA(&card);
    u8 *temp = NULL;

    // There's some funny padding indicator that must be
    //  prepended... hmm.
    if (!(temp = (u8*)malloc(inlen + 1)))
        return SC_ERROR_OUT_OF_MEMORY;
    temp[0] = '\0';
    memcpy(temp + 1, in, inlen);   
    in = temp;
    inlen += 1;

    // Craft apdu
    format_apdu(card, &apdu, APDU_CASE_4, 0x2A, 0x80, 0x86);
    apdu.lc = inlen;
    apdu.data = in;
    apdu.datalen = inlen;
    apdu.le = ((outlen >= 256) && !(card->caps & CARD_CAP_APDU_EXT)) ? 256 : outlen;
    apdu.resp = out;
    apdu.resplen = outlen;
    apdu.flags |= APDU_FLAGS_CHAINING;

    r = transmit_apdu(card, &apdu); 
    free(temp);
        
    LOG_TEST_RET(r, "APDU transmit failed\n");

    r = check_sw(card, apdu.sw1, apdu.sw2);
    LOG_TEST_RET(r, "Card returned error\n");
*/


}

