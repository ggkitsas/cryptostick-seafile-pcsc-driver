#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/pkcs12.h>

#include "common.h"
#include "openpgp.h"
#include "iso7816.h"

#include "cryptostick.h"

int csListDevices(cs_list *cryptosticks)
{
    int r;

    reader_list* readerList = (reader_list*)malloc(sizeof(reader_list));

    r = pcsc_detect_readers(readerList);
    if ( ! r == SC_SUCCESS) {
        free(readerList);
        return r;
    }

    
    int i;
    cryptosticks->numOfNodes = 0;
    cs_list_node* csCurrentNode;
    cs_list_node* previousNode;
    reader_list_node* readerCurrentNode = readerList->root;

    for( i=0; i<readerList->readerNum; i++)
    {   
        csCurrentNode = (cs_list_node*)malloc(sizeof(cs_list_node));
        r = connect_card(readerCurrentNode->reader, &(csCurrentNode->card));
        if(! r == SC_SUCCESS)
            continue;
   
        r = card_init(csCurrentNode->card);
        if(! r == SC_SUCCESS)
            continue;

        if(i == 0) {
            cryptosticks->root = csCurrentNode;
            previousNode = cryptosticks->root;
        } else {
            previousNode->next = csCurrentNode;
            previousNode = previousNode->next;
        }
        cryptosticks->numOfNodes++;
      

        if(i != readerList->readerNum -1) {
            readerCurrentNode = readerCurrentNode->next;
        }
    }

    return SC_SUCCESS;
}

int csGetSerialNo(card_t *card, unsigned char serialno[6])
{
    int r;
    memcpy(serialno, &(card->serialnr.value[2]), 6);
    return 0;
}

int csGetPublicKey(card_t *card, 
                    unsigned char** publicModulus, size_t* publicModulusLength,
                    unsigned char** publicExponent, size_t* publicExponentLength)
{
    int r,i;

    apdu_t apdu;

    u8 idbuf[2];
    unsigned tag = 0xb800; // Control reference template for confidentiality (CT)
    size_t buf_len=500;
    u8* buf;
    buf = (u8*)malloc((buf_len)*sizeof(u8));

    format_apdu(card, &apdu, APDU_CASE_4, 0x47, 0x81, 0x00);
    apdu.lc = 2;
    apdu.data = ushort2bebytes(idbuf, tag);
    apdu.datalen = 2;         
    apdu.le = ((buf_len >= 256) && !(card->caps & CARD_CAP_APDU_EXT)) ? 256 : buf_len;
    apdu.resp = buf;          
    apdu.resplen = buf_len;   


    r = transmit_apdu(card, &apdu);
    LOG_TEST_RET(r, "APDU transmit failed");

    r = check_sw(card, apdu.sw1, apdu.sw2);
    LOG_TEST_RET(r, "Card returned error");
    
    unsigned int cla;
    size_t taglen;
    sc_asn1_read_tag((const u8**)(&buf), buf_len, &cla, &tag, &taglen);
    if( cla != 0x60 || tag != 0x1f49)
        return -1;

    // Get modulus from response
    sc_asn1_read_tag((const u8**)(&buf), buf_len, &cla, &tag, &taglen);
    if( cla != 0x80 ||  tag != 0x01)
        return -1;
    *publicModulusLength = taglen;
    *publicModulus = (unsigned char*)malloc((taglen+1)*sizeof(unsigned char));
    memcpy(*publicModulus, buf, taglen);
    publicModulus[taglen]='\0';
    buf+=taglen;
    
    // Get exponent from response
    sc_asn1_read_tag((const u8**)(&buf), buf_len, &cla, &tag, &taglen);
    *publicExponent = (unsigned char*)malloc(taglen*sizeof(unsigned char));
    if( cla != 0x80 || tag != 0x02)
        return -1;
    *publicExponentLength = taglen;
    *publicExponent = (unsigned char*)malloc(taglen*sizeof(unsigned char));
    memcpy(*publicExponent, buf, taglen);
    buf+=taglen;

    return 0;
}

int csVerifyPIN(card_t *card, unsigned char* pin, int pinLength)
{
    int r;

    sc_pin_cmd_data pin_data;
    pin_data.cmd = SC_PIN_CMD_VERIFY;
    pin_data.pin_reference = 2;

    pin_data.pin1.data = (const u8*)pin ;
    pin_data.pin1.len = pinLength;
    pin_data.pin1.min_length = 6;
    pin_data.pin1.max_length = 32;
    pin_data.pin1.encoding = SC_PIN_ENCODING_ASCII;

    int tries_left;
    r = pgp_pin_cmd(card, &pin_data, &tries_left);

    return r;
}

int csVerifyAdminPIN(card_t *card, unsigned char* pin, int pinLength)
{
    int r;

    sc_pin_cmd_data pin_data;
    pin_data.cmd = SC_PIN_CMD_VERIFY;
    pin_data.pin_reference = 3;

    pin_data.pin1.data = (const u8*)pin ;
    pin_data.pin1.len = pinLength;
    pin_data.pin1.min_length = 6;
    pin_data.pin1.max_length = 32;
    pin_data.pin1.encoding = SC_PIN_ENCODING_ASCII;

    int tries_left;
    r = pgp_pin_cmd(card, &pin_data, &tries_left);

    return r;
}

int csUnblock(card_t* card, const char* new_pin, int newLength)
{
    int r;

    sc_pin_cmd_data pin_data;
    pin_data.cmd = SC_PIN_CMD_UNBLOCK;
    pin_data.pin_reference = 1;

    pin_data.pin2.data = (const u8*)new_pin ;
    pin_data.pin2.len = newLength;
    pin_data.pin2.min_length = 6;
    pin_data.pin2.max_length = 32;
    pin_data.pin2.encoding = SC_PIN_ENCODING_ASCII;

    int tries_left;
    r = pgp_pin_cmd(card, &pin_data, &tries_left);

    return r;

}


int csDecipher(card_t *card, unsigned char* input, size_t in_len,
                unsigned char* output, size_t out_len)
{
    return iso7816_decipher(card, input, in_len, output, out_len);
}

int csEncrypt(card_t* card, unsigned char* input, unsigned inputLength,
                            unsigned char** encrypted, unsigned* encryptedLength)
{
    int r,i;

    // Get public key
    unsigned char* modulus;
    unsigned char* exponent;
    size_t modlen, explen;
    r = csGetPublicKey(card, &modulus, &modlen, &exponent, &explen);

    RSA* rsa = NULL;
    *encryptedLength = inputLength % 256 == 0 ? inputLength : (inputLength/256 +1)*256;
    *encrypted = (unsigned char*)malloc(sizeof(unsigned char)*(*encryptedLength));
    unsigned char* n_hex;
    unsigned char* e_hex;
    
    n_hex = (unsigned char*)malloc(sizeof(unsigned char*)*modlen*2);
    for(i=0;i<modlen;i++)
        sprintf((char*)(n_hex + (i * 2)), "%02x", modulus[i]);

    e_hex = (unsigned char*)malloc(sizeof(unsigned char*)*explen*2);
    for(i=0;i<explen;i++)
        sprintf((char*)(e_hex + (i * 2)), "%02x", exponent[i]);
    
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

    int enc_length = RSA_public_encrypt(6, input, *encrypted, rsa, RSA_PKCS1_PADDING);
    *encryptedLength = enc_length;
    printf("encrypted: \n");
    for(i=0;i<*encryptedLength;i++)
        printf("%.2x ", (*encrypted)[i]);
    printf("\n\n\n\n\n\n");

    if(enc_length == -1) {
        char error[400];
        ERR_error_string(ERR_get_error(), error);
        printf("Public key encrypt failed with error: %s \n", error );
        return -1;
    }

    return 0;
}

int csHashPublicKey(card_t *card, unsigned char hashedKey[65])
{
    int r;

    // Get public key   
    unsigned char* modulus;
    unsigned char* exponent;
    size_t modlen, explen;
    r = csGetPublicKey(card, &modulus, &modlen, &exponent, &explen);

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, (const char*)modulus, strlen((const char*)modulus));
    SHA256_Final(hash, &sha256);
    int i = 0;
    for(i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        sprintf((char*)(hashedKey + (i * 2)), "%02x", hash[i]);
    }
    hashedKey[64] = 0;
}

int csGenerateAndImportKeyPair(card_t* card, unsigned int key_length)
{
    int r;

    // Generate Key Pair
    ERR_load_crypto_strings();
    char error[400];

    int modulus_length = key_length; //2048; // bits

    unsigned long e = 65537;
    const char* e_hex = "100001";

//  RSA *rsa = NULL;
    RSA* rsa = RSA_new();

    BIGNUM *e_bn=NULL;
    r = BN_hex2bn(&e_bn, e_hex);
    if(r == 0) {
        printf("BN_hex2bn failed\n");
        return -1;
    }

    char rand_buf[300];
    RAND_seed(rand_buf, 300);
    if( RAND_status() != 1)
        printf("NOT ENOUGH ENTROPY");

    // rsa = RSA_generate_key(modulus_length, e, NULL /*keygen_progress*/, NULL);
    r = RSA_generate_key_ex(rsa, modulus_length, e_bn, NULL);

    if (rsa == NULL)
    {
        ERR_error_string(ERR_get_error(), error);
        printf("Failed to generate RSA key pair.OpenSSL error:\n %s\n", error);
        return -1;
    }

    unsigned char *n_hex = (unsigned char*)calloc(1, 2*key_length/8);
    unsigned char *d_hex = (unsigned char*)calloc(1, 2*key_length/8);
    unsigned char *p_hex = (unsigned char*)calloc(1, 2*key_length/8);
    unsigned char *q_hex = (unsigned char*)calloc(1, 2*key_length/8);
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
    if (!(  p_hex = (unsigned char*) BN_bn2hex((const BIGNUM*)rsa->q)  ))
    {
        printf("Private exponent parsing error\n");
        return -1;
    }
    if (!(  q_hex = (unsigned char*) BN_bn2hex((const BIGNUM*)rsa->p)  ))
    {
        printf("Private exponent parsing error\n");
        return -1;
    }
    printf("Public modulus:\n\t%s\n", n_hex);
    printf("Private exponent:\n\t%s\n", d_hex);
    printf("Prime p:\n\t%s\n", p_hex);
    printf("Prime q:\n\t%s\n", q_hex);


    // Import Key Pair
    sc_cardctl_openpgp_keystore_info_t key_info;
    key_info.keytype = SC_OPENPGP_KEY_ENCR;
    key_info.keyformat = SC_OPENPGP_KEYFORMAT_STD;
    
    /* n */
    unsigned char* n_bin = (unsigned char*)calloc(1, modulus_length/8);
    key_info.n_len = BN_bn2bin(rsa->n, n_bin);
    key_info.n = n_bin;
 
    /* e */
    key_info.e = (u8*)calloc(1, 4);
    key_info.e_len = 4;  
    if ((r = hex_to_bin(e_hex, key_info.e, &(key_info.e_len))) != SC_SUCCESS)
    {
        printf("hex_to_bin ERROR\n");
    if(r == SC_ERROR_BUFFER_TOO_SMALL)
        printf("SC_ERROR_BUFFER_TOO_SMALL\n");
        return -1;
    }

    /* p */
    unsigned char* p_bin = (unsigned char*)calloc(1, strlen((const char*)p_hex)/2);
    key_info.p_len = BN_bn2bin(rsa->p, p_bin);
    key_info.p = p_bin;

    /* q */
    unsigned char* q_bin = (unsigned char*)calloc(1, strlen((const char*)q_hex)/2);
    key_info.q_len = BN_bn2bin(rsa->q, q_bin);
    key_info.q = q_bin;

    
    printf("Lengths: n = %lu\ne= %lu\np = %lu\nq = %lu\n",key_info.n_len, key_info.e_len, key_info.p_len, key_info.q_len);

    if( (r = pgp_store_key(card, &key_info)) != 0)
        printf("pgp_store_key error: %d\n",r);

    // Cleanups
    free(rsa);
    free(n_bin);
    free(n_hex);
    free(d_hex);
}


int csExportKeyPairToFile(const char* file_path)
{
    FILE* fp = fopen(file_path, "w+");
    PKCS12* p12;
    i2d_PKCS12_fp(fp, p12);
}
