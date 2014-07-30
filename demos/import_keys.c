#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/rsa.h>
#include <openssl/err.h>

#include "common.h"
#include "card.h"

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
    BN_bn2bin(rsa->n. n_bin);
    key_info.n = n_bin;
    key_info.n_len = modulus_length;
    
//    unsigned char* e_bin = (unsigned char8)calloc(1, );
//    BN_bn2bin(rsa->e, e_bin);
    
    key_info.e = (size_t)e;
    key_info.e_len = ;
    

    // Cleanups
    free(rsa);

    return 0;
}
