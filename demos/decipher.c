
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "openssl/rsa.h"
#include "openssl/sha.h"
#include "openssl/bio.h"
#include "openssl/pem.h"
#include "openssl/err.h"

#include "common.h"
#include "card.h"
#include "openpgp.h"
#include "pcsc-wrapper.h"
#include "iso7816.h"
#include "cryptostick.h"

void sha256(char *string, char outputBuffer[65])
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, string, strlen(string));
    SHA256_Final(hash, &sha256);
    int i = 0;
    for(i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        sprintf(outputBuffer + (i * 2), "%02x", hash[i]);
    }
    outputBuffer[64] = 0;
}

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
    unsigned char* pin = getline(6);
    printf("Please provide user PIN:\n");
//    r = csVerifyPIN(card, (unsigned char*)"123456", 6);
    r = csVerifyPIN(card, pin, strlen((const char*)pin));
    LOG_TEST_RET(r, "PIN verification failed");    

// Get public key
    unsigned char* modulus;
    unsigned char* exponent;
    size_t modlen, explen;
    r = csGetPublicKey(card, &modulus, &modlen, &exponent, &explen);

    printf("%lu %lu\n",modlen, explen);
    for(i=0;i<modlen;i++)
        printf("%.2x ",modulus[i]);
    printf("\n");
    for(i=0;i<explen;i++)
        printf("%.2x ",exponent[i]);
    printf("\n");

/*
    unsigned int cla;
    unsigned int tag;
    size_t taglen;
    sc_asn1_read_tag((const u8**)(&publicKey2), 270, &cla, &tag, &taglen);
    printf("cla=%.2x, tag=%.2x, taglen=%lu\n", cla, tag, taglen);
    sc_asn1_read_tag((const u8**)(&publicKey2), 270, &cla, &tag, &taglen);
    printf("cla=%.2x, tag=%.2x, taglen=%lu\n", cla, tag, taglen);
    for(i=0;i<taglen;i++)
        printf("%.2x ", (publicKey2++)[0]);
    printf("\n\n");

    sc_asn1_read_tag((const u8**)(&publicKey2), 270, &cla, &tag, &taglen);
    printf("cla=%.2x, tag=%.2x, taglen=%lu\n", cla, tag, taglen);
    for(i=0;i<taglen;i++)
        printf("%.2x ", (publicKey2++)[0]);
    printf("\n\n");
*/
    LOG_TEST_RET(r, "Fetching public key failed");


// ENCRYPT
printf("-------------------------- Encrypting ------------------------------------\n");

    RSA* rsa = NULL;
    unsigned char encrypted[4098] = {};


// Convert public key to rsa key
    unsigned char* n_hex;// = modulus;
    unsigned char* e_hex;// = exponent;//"65537";

    n_hex = (unsigned char*)malloc(sizeof(unsigned char*)*modlen*2);
    for(i=0;i<modlen;i++)
    {
        sprintf((char*)(n_hex + (i * 2)), "%02x", modulus[i]);
    }
    printf("%s\n", modulus);

    e_hex = (unsigned char*)malloc(sizeof(unsigned char*)*explen*2);
    for(i=0;i<explen;i++)
    {
        sprintf((char*)(e_hex + (i * 2)), "%02x", exponent[i]);
    }
    printf("%s\n", exponent);

    char pubKeyHash[65];
    sha256((char*)modulus, pubKeyHash);
    printf("Hashed Public Key: ");
    for(i=0;i<65;i++)
        printf("%.2x ", pubKeyHash[i]);
    printf("\n");

    ERR_load_crypto_strings();
    rsa = RSA_new();

    if(!BN_hex2bn(&rsa->n, (const char*)n_hex)) {
        printf("modulo parsing error\n");
        return -1;
    }

    if (!BN_hex2bn(&rsa->e, (const char*)e_hex)) {
        printf("exponent parsing error\n");
        return -1;
    }

    // Host encryption
    int rsaPadding = RSA_PKCS1_PADDING;
    int enc_length = RSA_public_encrypt(6, (unsigned char*)"blabla", encrypted, rsa, rsaPadding);
printf("------------------------------------------------------------------------\n\n enc length = %d \n\n------------------------------------------------------------\n",enc_length);
    if(enc_length == -1) {
        char error[400];
        ERR_error_string(ERR_get_error(), error);
        printf("Public key encrypt failed with error: %s \n", error );
        return -1;
    }
    printf("\n\n\n Encrypted: (len=%d) \n",enc_length); 
    for(i=0;i<enc_length;i++)
       printf("%.2x ",encrypted[i]);
    printf("\n\n\n");


    // Card decryption (DECIPHER)
    u8 *in = (u8*)encrypted;
    u8 out[6];
    size_t inlen=enc_length;
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
printf("apdu.le = %lu\n",apdu.le);
#ifdef GNUK
    apdu.flags |= APDU_FLAGS_CHAINING;
#endif

    r = transmit_apdu(card, &apdu); 
    free(temp);
        
    LOG_TEST_RET(r, "APDU transmit failed\n");

    r = check_sw(card, apdu.sw1, apdu.sw2);
*/

    printf("%s\n", out);

    LOG_TEST_RET(r, "Card returned error\n");

}

