#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/rsa.h>
#include <openssl/err.h>

#include "common.h"
#include "card.h"
#include "openpgp.h"
#include "cryptostick.h"

#include "import_keys_lib.h"

/*
void keygen_progress(int , int, void* cb_arg)
{}
*/


int main()
{

    // Seed RNG


    // Generate Key Pair
    ERR_load_crypto_strings();
    char error[400];

    int modulus_length = 2048; // bits

    unsigned long e = 65537;
    const char* e_hex = "100001";
    RSA *rsa = NULL;
    rsa = RSA_generate_key(modulus_length, e, NULL /*keygen_progress*/, NULL);
    if (rsa == NULL)
    {
        ERR_error_string(ERR_get_error(), error);
        printf("Failed to generate RSA key pair.OpenSSL error:\n %s\n", error);
        return -1;
    }

    unsigned char *n_hex = (unsigned char*)calloc(1, 2*2048/8);
    unsigned char *d_hex = (unsigned char*)calloc(1, 2*2048/8);
    if (!(  n_hex = (unsigned char*) BN_bn2hex((const BIGNUM*)rsa->n)  ))
    {
        printf("Modulo parsing error\n");
        return -1;
    }
    if (!(  d_hex = (unsigned char*) BN_bn2hex((const BIGNUM*)rsa->d)  ))
    {
        printf("Private exponent parsing error\n");
        return -1;
    }

    printf("Public modulus:\n\t%s\n", n_hex);
    printf("Private exponent:\n\t%s\n", d_hex);

    // Import Key Pair
    sc_cardctl_openpgp_keystore_info_t key_info;
    key_info.keytype = SC_OPENPGP_KEY_ENCR;
    key_info.keyformat = SC_OPENPGP_KEYFORMAT_STDN;
    
    unsigned char* n_bin = (unsigned char*)calloc(1, modulus_length);
    BN_bn2bin(rsa->n, n_bin);
    key_info.n = n_bin;
    key_info.n_len = modulus_length;
    
    hex_to_bin(e_hex, key_info.e, &(key_info.e_len));


    // List readers
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

for(int j=0; j<6;j++)
    printf("%.2x ", card->serialnr.value[j]);
printf("\n");
   
    if( (r = pgp_store_key(card, &key_info)) != 0)
        printf("pgp_store_key error: %d\n",r);

    // Cleanups
    free(rsa);
    free(n_bin);
    free(n_hex);
    free(d_hex);

    return 0;
}
