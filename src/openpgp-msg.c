#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#include "openpgp-msg.h"


static
unsigned int bits2bytes(unsigned int bits)
{
    unsigned int lower_num = bits / 8;
    return (lower_num * 8) == bits ? lower_num : lower_num + 1;
}

/*
 * Convert a byte array @byte_arr of length @len
 * to an unsinged int
 */
static 
unsigned int bytearr2uint(unsigned char* byte_arr, unsigned int len)
{
    int i;
    unsigned int value=0;
    unsigned int weight=1;
    for(i=len-1; i>=0; i--) {
        value += byte_arr[i] * weight;
        weight *= 256;
    }
    return value;
}

/*
 * Converts an integer to a 2-byte unsigned char arraya
 * Int must be at the range of [0, 65535]
 * The byte array is fresh allocated
 */
static 
unsigned int int2bytearr2(int value, unsigned char arr[2])
{
    if(value > 65535 || value < 0 )
        return -1;
    
    arr[1] = value / 256;
    arr[0] = value-arr[1];
}


/* 
 * Read next @byte_num bytes from file @fp
 * Returns @byte_array.
 * @byte_array must be already allocated before calling @file_read_bytes
 */
static
int file_read_bytes(FILE* fp, unsigned int byte_num, unsigned char* byte_array)
{
    int i;
    for(i=0; i<byte_num; i++) {
        byte_array[i] = fgetc(fp);
        if(byte_array[i] == EOF) {
            free(byte_array);
            return FILE_READ_BYTES_PREMATURE_EOF;
        }
    }
    return 0;
}


/* 
 * Read next @byte_num bytes from file @fp
 * Returns a fresh allocated @byte_array
 */
static
int file_read_bytes_alloc(FILE* fp, unsigned int byte_num, unsigned char** byte_array)
{
    *byte_array = (unsigned char*) calloc(1, byte_num * sizeof(unsigned char));
    file_read_bytes(fp, byte_num, *byte_array);
}

static
int file_write_bytes(FILE* fp, unsigned int byte_num, unsigned char* byte_array)
{
    int i,r;
    for(i=0; i<byte_num; i++) {
        r = fputc(byte_array[i], fp);
        if(r == EOF) {
            free(byte_array);
            return FILE_READ_BYTES_PREMATURE_EOF;
        }
    }
    return 0;
   
}

static
void print_bytearr(const char* title, unsigned char* value, unsigned int value_len)
{
    int i;
    printf("%s", title);
    printf(": ");
    for(i=0; i<value_len; i++)
        printf("%.2x ", value[i]);
    printf("\n");
        
}

static
void print_mpi(const char* title, pgp_mpi* mpi)
{
    printf("%s:\n",title);
    print_bytearr("\tlength", mpi->length, 2);
    print_bytearr("\tvalue", mpi->value, bits2bytes( bytearr2uint(mpi->length, 2) ));
}

static
void print_s2k(pgp_s2k* s2k)
{
    printf("S2K struct:\n");
    printf("\tType: %.2x\n",s2k->type);
    printf("\tHash algorithm: %.2x\n",s2k->hash_algo);
    print_bytearr("\tSalt", s2k->salt, 8);
    printf("\tCount: %.2x\n",s2k->count);
}

void pgp_print_pubkey_packet(pgp_pubkey_packet* pgp_packet)
{
    printf("Version: %.2x\n", pgp_packet->version);
    print_bytearr("Time", pgp_packet->creation_time, 4);
    printf("Algorithm: %d\n", pgp_packet->algo);
    print_mpi("Modulus", pgp_packet->modulus);
    print_mpi("Exponent", pgp_packet->exponent);
}


static
void print_seckey_data(pgp_seckey_packet* pkt)
{
    if (pkt->s2k_usage == 0xfe || pkt->s2k_usage == 0x00)
        print_bytearr("Hash",pkt->seckey_data->hash, 20);
    else 
        print_bytearr("Checksum", pkt->seckey_data->hash, 2);
        
    print_mpi("RSA d", pkt->seckey_data->rsa_d);
    print_mpi("RSA p", pkt->seckey_data->rsa_p);
    print_mpi("RSA q", pkt->seckey_data->rsa_q);
    print_mpi("RSA u", pkt->seckey_data->rsa_u);
}

void pgp_print_seckey_packet(pgp_seckey_packet* pkt)
{
    pgp_print_pubkey_packet(pkt->pubkey_packet);

    printf("S2K Usage: %.2x\n", pkt->s2k_usage);

    if(pkt->enc_algo)
        printf("Encryption Algorithm: %.2x\n", pkt->enc_algo[0]);

    if(pkt->s2k)
        print_s2k(pkt->s2k);

    if(pkt->iv)
        print_bytearr("IV", pkt->iv, get_block_size(pkt->enc_algo[0]) );

    print_seckey_data(pkt);
}


int pgp_read_mpi(FILE* fp, pgp_mpi** mpi)
{
    int r;
    pgp_mpi* tmp_mpi = (pgp_mpi*)calloc(1, sizeof(pgp_mpi));
    r = file_read_bytes(fp, 2, tmp_mpi->length);
    if(r != 0)
        return r;

    unsigned int value_len = bits2bytes( bytearr2uint(tmp_mpi->length, 2)); //bytes
    r = file_read_bytes_alloc(fp, value_len, &(tmp_mpi->value));
    if(r != 0)
        return r;
    *mpi = tmp_mpi;
    return 0;
}

int pgp_write_mpi(FILE* fp, pgp_mpi* mpi)
{
    int r;
    r = file_write_bytes(fp, 2, mpi->length);
    if(r != 0)
        return r;

    unsigned int value_len = bits2bytes( bytearr2uint(mpi->length, 2)); //bytes
    r = file_write_bytes(fp, value_len, mpi->value);
    if(r != 0)
        return r;
    return 0;
}


int pgp_read_s2k(FILE* fp, pgp_s2k** s2k)
{
    pgp_s2k* tmp_s2k = (pgp_s2k*)calloc(1, sizeof(pgp_s2k));

    tmp_s2k->type = fgetc(fp);
    if( tmp_s2k->type == S2K_TYPE_GNUPG )
    {
        printf("GnuPG keyrings not supported yet\n");
        return UNSUPPROTED_S2K;
    } else if ( tmp_s2k->type != S2K_TYPE_SIMPLE &&
                tmp_s2k->type != S2K_TYPE_SALTED &&
                tmp_s2k->type != S2K_TYPE_ITERATED_SALTED) {
        printf("Unsupported s2k type\n");
        return UNSUPPROTED_S2K;
    }

    tmp_s2k->hash_algo = fgetc(fp);

    if( tmp_s2k->type > S2K_TYPE_SIMPLE )
        file_read_bytes(fp, 8, tmp_s2k->salt);
//    else
//        tmp_s2k->salt = NULL;

    if( tmp_s2k->type == S2K_TYPE_ITERATED_SALTED )
        tmp_s2k->count = fgetc(fp);
    else
        tmp_s2k->count = 0;

    *s2k = tmp_s2k;
    return 0;
}

int pgp_write_s2k(FILE* fp, pgp_s2k* s2k)
{
    int r;
    r = fputc(s2k->type, fp);
    if( s2k->type == S2K_TYPE_GNUPG )
    {
        printf("GnuPG keyrings not supported yet\n");
        return UNSUPPROTED_S2K;
    } else if ( s2k->type != S2K_TYPE_SIMPLE &&
                s2k->type != S2K_TYPE_SALTED &&
                s2k->type != S2K_TYPE_ITERATED_SALTED) {
        printf("Unsupported s2k type\n");
        return UNSUPPROTED_S2K;
    }

    r = fputc(s2k->hash_algo, fp);

    if( s2k->type > S2K_TYPE_SIMPLE )
        file_write_bytes(fp, 8, s2k->salt);

    if( s2k->type == S2K_TYPE_ITERATED_SALTED )
        r = fputc(s2k->count, fp);

    return 0;
}

int pgp_read_pubkey_packet(FILE* fp, pgp_pubkey_packet** pubkey_packet)
{
    pgp_pubkey_packet* pubkey_pkt = (pgp_pubkey_packet*) calloc(1, sizeof(pgp_pubkey_packet));

    pubkey_pkt->version = fgetc(fp);
    file_read_bytes(fp, 4, pubkey_pkt->creation_time);
    if (pubkey_pkt->version == 0x03 )
        file_read_bytes_alloc(fp, 2, &(pubkey_pkt->validity_period));
    else 
        if (pubkey_pkt->version == 0x04)
            pubkey_pkt->validity_period = NULL;
        else {
            printf("Public packet does not have a valid version (version found = %d)\n",
                        pubkey_pkt->version);
            return -1;
        }
    pubkey_pkt->algo = fgetc(fp);
    pgp_read_mpi(fp, &(pubkey_pkt->modulus));
    pgp_read_mpi(fp, &(pubkey_pkt->exponent));

    *pubkey_packet = pubkey_pkt;
    return 0;
}

int pgp_write_pubkey_packet(FILE* fp, pgp_pubkey_packet* pubkey_pkt)
{
    int r;
    r = fputc(pubkey_pkt->version, fp);

    file_write_bytes(fp, 4, pubkey_pkt->creation_time);
    if (pubkey_pkt->version == 0x03 )
        file_write_bytes(fp, 2, pubkey_pkt->validity_period);
    
    r = fputc(pubkey_pkt->algo, fp);
    pgp_write_mpi(fp, pubkey_pkt->modulus);
    pgp_write_mpi(fp, pubkey_pkt->exponent);

    return 0;
}

static
const char* ask_passphrase()
{
    printf("Insert passphrase for the secret key:\n");
    int size = 8;
    if (size <= 0) size = 1;
    unsigned char *str;
    int ch;
    size_t len = 0;
    str = (unsigned char*)realloc(NULL, sizeof(char)*size); //size is start size
    if (!str) return (const char*)str;
    while ((ch = getchar()) && ch != '\n') {
        str[len++] = ch;
        if(len == size){
            str = (unsigned char*)realloc(str, sizeof(char)*(size*=2));
            if (!str) return (const char*)str;          
        }
    }
    str[len++]='\0';

    return (const char*)realloc(str, sizeof(char)*len);
}

static
void checksum_update(unsigned int chksum, unsigned char* data, unsigned int length)
{
    int i;
    for(i=0; i<length; i++) {
        chksum += data[i];
    }
    chksum = chksum % 0x10000;
}

static
void pgp_hash(const char* passphrase, unsigned char* seed, pgp_s2k* s2k, unsigned char** hash)
{
    int i;

    EVP_MD_CTX *mdctx;
    const EVP_MD *md;
    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned md_len;

    OpenSSL_add_all_digests();
    md = EVP_get_digestbyname( get_hash_name(s2k->hash_algo) );
    if(!md) {
    }
    mdctx = EVP_MD_CTX_create();
    EVP_DigestInit_ex(mdctx, md, NULL);

    // Preloading context with seed
    if(seed)
        EVP_DigestUpdate(mdctx, seed, strlen(passphrase));

    // Caclulate hash
    if (s2k->type == S2K_TYPE_SIMPLE) {
        // Hash only the passphrase
        EVP_DigestUpdate(mdctx, passphrase, strlen(passphrase));
    } else if (s2k->type == S2K_TYPE_SALTED) {
        // First the salt, then the passphrase
        EVP_DigestUpdate(mdctx, s2k->salt, strlen((const char*)s2k->salt));
        EVP_DigestUpdate(mdctx, passphrase, strlen(passphrase));
    } else if (s2k->type == S2K_TYPE_ITERATED_SALTED) {
        int count =  (16 + (s2k->count & 15) ) << ((s2k->count >> 4) + 6);
        // Hash 'count' octets of 
        // [ (salt || passphrase) || (salt || passphrase) || ... ]
        unsigned int salt_pass_concat_len = 8 + strlen(passphrase);
        unsigned char* salt_pass_concat = (unsigned char*) malloc(salt_pass_concat_len);
        memcpy(salt_pass_concat, s2k->salt, 8);
        memcpy(&(salt_pass_concat[8]), passphrase, strlen(passphrase));

        for(i=0; i<count; i+=salt_pass_concat_len)
        {
            if ( count >= i+salt_pass_concat_len)
                EVP_DigestUpdate(mdctx, salt_pass_concat, salt_pass_concat_len);
            else
                EVP_DigestUpdate(mdctx, salt_pass_concat, count-i);
        }
    } else {
        printf("Unsupported S2K type\n");
        return;
    }

    EVP_DigestFinal_ex(mdctx, md_value, &md_len);
    EVP_MD_CTX_destroy(mdctx);

    *hash = (unsigned char*) malloc(sizeof(unsigned char) * md_len);
    memcpy(*hash, md_value, md_len);
}

static
int pgp_derive_key(const char* passphrase, pgp_seckey_packet* pkt, unsigned char** key)
{
    int i;

    int key_size = get_key_size(pkt->enc_algo[0]);
    *key = (unsigned char*) calloc(key_size, sizeof(unsigned char) );
    
    int hash_size = get_hash_size(pkt->s2k->hash_algo);
    unsigned char* hash;

    if (hash_size >= key_size) {
        // Hash once and truncate if necessary
        pgp_hash(passphrase, NULL,  pkt->s2k, &hash);
        memcpy(*key, hash, key_size);
    } else {
        // Hash until we have enough octets for the symmetric key
        // truncate at the end if needed

        int num_octets_cpy;
        unsigned char* seed = (unsigned char*)"";
        for(i=0; i<key_size ; i+=hash_size) {
            pgp_hash(passphrase, seed, pkt->s2k, &hash);
            num_octets_cpy = key_size > i+hash_size ? hash_size: key_size-i;
            memcpy(&(key[i]), hash, hash_size);
            free(seed);
            seed = (unsigned char*) calloc((i/hash_size)+1, sizeof(unsigned char) );
            free(hash);
        }
        free(seed);
    }
    return key_size;
}


/*
 * Initializes enc/deciphering routine
 * cipher_id: Symmetric encryption algorithm ID, according to openpgp-msg.h
 * enc_dec: 1->encryption, 0->decryption
 * Returns a cipher context
 */
static
EVP_CIPHER_CTX* pgp_cipher_init(unsigned int cipher_id, 
                    unsigned char* key, unsigned char* iv, int enc_dec)
{
    ERR_load_crypto_strings();
    char error[400];

    int r;
    EVP_CIPHER_CTX *cipherctx;
    const EVP_CIPHER *cipher;

    OpenSSL_add_all_ciphers();
    cipher = EVP_get_cipherbyname( get_cipher_name(cipher_id) );
    cipherctx = EVP_CIPHER_CTX_new();
    r = EVP_CipherInit_ex(cipherctx, cipher, NULL, key, iv, enc_dec);
    if(!r) {
        ERR_error_string(ERR_get_error(), error);
        printf("EVP_CipherInit_ex failed %s\n",error);
        return NULL;
    }
    return cipherctx;
}

static
void pgp_cipher_update( EVP_CIPHER_CTX* cipherctx, 
                        unsigned char* data_in, int inlen,
                        unsigned char** data_out, int* outlen)
{
    *data_out = (unsigned char*)malloc(sizeof(unsigned char) * inlen);
    EVP_CipherUpdate(cipherctx, *data_out, outlen, data_in, inlen);
}

static
void pgp_cipher_finish(EVP_CIPHER_CTX* cipherctx)
{
    if(cipherctx) { 
        // EVP_CipherFinal_ex(cipherctx, dec_data, &dec_length);
        EVP_CIPHER_CTX_cleanup(cipherctx);
        EVP_CIPHER_CTX_free(cipherctx);
    }
}

static
int file_read_bytes_decrypt( EVP_CIPHER_CTX* cipherctx,
                            FILE* fp, int length, unsigned char* out)
{
    int r;

    unsigned char* enc_data;
    int outlen;
    file_read_bytes_alloc(fp, length, &enc_data);
    r = EVP_CipherUpdate(cipherctx, out, &outlen, enc_data, length);
    return 1-r; // we want to return 0->success, 1->failure 
                // (complemetary of EVP_CipherUpdate)
}

static
int file_read_bytes_decrypt_alloc( EVP_CIPHER_CTX* cipherctx,
                            FILE* fp, int length, unsigned char** out)
{
    int r;
    *out = (unsigned char*) malloc (length * sizeof(unsigned char));
    r =file_read_bytes_decrypt(cipherctx, fp, length, *out);
    return r;
}

static
int file_write_bytes_encrypt( EVP_CIPHER_CTX* cipherctx,
                            FILE* fp, int length, unsigned char* data)
{
    int r;

    unsigned char* enc_data = (unsigned char*) malloc(length * sizeof(unsigned char));
    int outlen;
    r = EVP_CipherUpdate(cipherctx, enc_data, &outlen, data, length);
    file_write_bytes(fp, length, enc_data);
    return 1-r; // we want to return 0->success, 1->failure 
                // (complemetary of EVP_CipherUpdate)
}

int pgp_read_mpi_decrypt(EVP_CIPHER_CTX* cipherctx, FILE* fp, pgp_mpi** mpi)
{
    int r;
    pgp_mpi* tmp_mpi = (pgp_mpi*)calloc(1, sizeof(pgp_mpi));
    r = file_read_bytes_decrypt(cipherctx, fp, 2, tmp_mpi->length);
    if(r != 0)
        return r;

    unsigned int value_len = bits2bytes( bytearr2uint(tmp_mpi->length, 2)); //bytes
    r = file_read_bytes_decrypt_alloc(cipherctx, fp, value_len, &(tmp_mpi->value));
    if(r != 0)
        return r;
    *mpi = tmp_mpi;
    return 0;
}


int pgp_write_mpi_encrypt(EVP_CIPHER_CTX* cipherctx, FILE* fp, pgp_mpi* mpi)
{
    int r;
    r = file_write_bytes_encrypt(cipherctx, fp, 2, mpi->length);
    if(r != 0)
        return r;

    unsigned int value_len = bits2bytes( bytearr2uint(mpi->length, 2)); //bytes
    r = file_write_bytes_encrypt(cipherctx, fp, value_len, mpi->value);
    if(r != 0)
        return r;
    return 0;
}


/*
 * Read secret key packet data from file @fp
 * Decrypt if necessary using @keya
 * Returns updated @seckey_packet
 */
static
int pgp_read_seckey_data(FILE* fp, pgp_seckey_packet* seckey_packet, unsigned char* key)
{
    seckey_packet->seckey_data = (pgp_seckey_data*)calloc(1, sizeof(pgp_seckey_data));

    if(seckey_packet->s2k_usage == 0x00) { // Plain
        pgp_read_mpi(fp, &(seckey_packet->seckey_data->rsa_d));
        pgp_read_mpi(fp, &(seckey_packet->seckey_data->rsa_p));
        pgp_read_mpi(fp, &(seckey_packet->seckey_data->rsa_q));
        pgp_read_mpi(fp, &(seckey_packet->seckey_data->rsa_u));

        file_read_bytes_alloc(fp, 2, &(seckey_packet->seckey_data->hash)); // 2 octet checksum
    } else {

        EVP_CIPHER_CTX* cipherctx = pgp_cipher_init(seckey_packet->enc_algo[0],
                                key, seckey_packet->iv, 0);

        pgp_read_mpi_decrypt(cipherctx, fp, &(seckey_packet->seckey_data->rsa_d));
        pgp_read_mpi_decrypt(cipherctx, fp, &(seckey_packet->seckey_data->rsa_p));
        pgp_read_mpi_decrypt(cipherctx, fp, &(seckey_packet->seckey_data->rsa_q));
        pgp_read_mpi_decrypt(cipherctx, fp, &(seckey_packet->seckey_data->rsa_u));

        if (seckey_packet->s2k_usage == 0xfe) { // sha1 digest
            file_read_bytes_decrypt_alloc(cipherctx, fp, 20, &(seckey_packet->seckey_data->hash));
        } else { // 2 octet checksum
            file_read_bytes_decrypt_alloc(cipherctx, fp, 2, &(seckey_packet->seckey_data->hash));
        }

        pgp_cipher_finish(cipherctx);
    }

    // Verify checksum/sha1-hash
    // TODO: missing all the other cases (checksum)
    if (seckey_packet->s2k_usage == 0x00 || 
        seckey_packet->s2k_usage == 0xff) {
        // 2 octet checksum
        unsigned int chksum = 0;
        checksum_update(chksum, seckey_packet->seckey_data->rsa_d->length, 2);
        checksum_update(chksum, seckey_packet->seckey_data->rsa_d->value, 
                    bits2bytes( bytearr2uint(seckey_packet->seckey_data->rsa_d->length, 2)));
        checksum_update(chksum, seckey_packet->seckey_data->rsa_p->length, 2);
        checksum_update(chksum, seckey_packet->seckey_data->rsa_p->value, 
                    bits2bytes( bytearr2uint(seckey_packet->seckey_data->rsa_p->length, 2)));
        checksum_update(chksum, seckey_packet->seckey_data->rsa_q->length, 2);
        checksum_update(chksum, seckey_packet->seckey_data->rsa_q->value, 
                    bits2bytes( bytearr2uint(seckey_packet->seckey_data->rsa_q->length, 2)));
        checksum_update(chksum, seckey_packet->seckey_data->rsa_u->length, 2);
        checksum_update(chksum, seckey_packet->seckey_data->rsa_u->value, 
                    bits2bytes( bytearr2uint(seckey_packet->seckey_data->rsa_u->length, 2)));

        if (bytearr2uint(seckey_packet->seckey_data->hash,2) != chksum) {
            printf("Verifcation of secret key data failed\n");
            return -1;
        }

    } else if (seckey_packet->s2k_usage == 0xfe) {
        // 20 octet sha1 digest
        int r;
        ERR_load_crypto_strings();
        char error[400];

        unsigned char md[20];
        SHA_CTX shactx;
        r = SHA1_Init(&shactx);
        if(!r) {
            ERR_error_string(ERR_get_error(), error);
            printf("SHA1_Init failed %s\n",error);
        }

        SHA1_Update(&shactx, seckey_packet->seckey_data->rsa_d->length, 2);
        SHA1_Update(&shactx, seckey_packet->seckey_data->rsa_d->value, 
                bits2bytes( bytearr2uint(seckey_packet->seckey_data->rsa_d->length, 2)));
        SHA1_Update(&shactx, seckey_packet->seckey_data->rsa_p->length, 2);
        SHA1_Update(&shactx, seckey_packet->seckey_data->rsa_p->value, 
                bits2bytes( bytearr2uint(seckey_packet->seckey_data->rsa_p->length, 2)));
        SHA1_Update(&shactx, seckey_packet->seckey_data->rsa_q->length, 2);
        SHA1_Update(&shactx, seckey_packet->seckey_data->rsa_q->value, 
                bits2bytes( bytearr2uint(seckey_packet->seckey_data->rsa_q->length, 2)));
        SHA1_Update(&shactx, seckey_packet->seckey_data->rsa_u->length, 2);
        SHA1_Update(&shactx, seckey_packet->seckey_data->rsa_u->value, 
                bits2bytes( bytearr2uint(seckey_packet->seckey_data->rsa_u->length, 2)));
        SHA1_Final(md, &shactx);

        if (memcmp(seckey_packet->seckey_data->hash, md, 20) != 0) {
            printf("Verifcation of secret key data failed\n");
            return -1;
        }
    }
}


static
int pgp_write_seckey_data(FILE* fp, pgp_seckey_packet* seckey_packet, unsigned char* key)
{
//    seckey_packet->seckey_data = (pgp_seckey_data*)calloc(1, sizeof(pgp_seckey_data));
    pgp_seckey_data* seckey_data = seckey_packet->seckey_data;

    EVP_CIPHER_CTX* cipherctx = NULL;

    if(seckey_packet->s2k_usage == 0x00) { // Plain
        pgp_write_mpi(fp, seckey_data->rsa_d);
        pgp_write_mpi(fp, seckey_data->rsa_p);
        pgp_write_mpi(fp, seckey_data->rsa_q);
        pgp_write_mpi(fp, seckey_data->rsa_u);

    } else {

        cipherctx = pgp_cipher_init(seckey_packet->enc_algo[0],
                                key, seckey_packet->iv, 1);

        pgp_write_mpi_encrypt(cipherctx, fp, seckey_data->rsa_d);
        pgp_write_mpi_encrypt(cipherctx, fp, seckey_data->rsa_p);
        pgp_write_mpi_encrypt(cipherctx, fp, seckey_data->rsa_q);
        pgp_write_mpi_encrypt(cipherctx, fp, seckey_data->rsa_u);

    }

    // Calulate and write checksum/sha1-hash
    // TODO: missing all the other cases (checksum)
    if (seckey_packet->s2k_usage == 0x00 || 
        seckey_packet->s2k_usage == 0xff) {
        // 2 octet checksum
        unsigned int chksum = 0;
        checksum_update(chksum, seckey_data->rsa_d->length, 2);
        checksum_update(chksum, seckey_data->rsa_d->value, 
                    bits2bytes( bytearr2uint(seckey_data->rsa_d->length, 2)));
        checksum_update(chksum, seckey_data->rsa_p->length, 2);
        checksum_update(chksum, seckey_data->rsa_p->value, 
                    bits2bytes( bytearr2uint(seckey_data->rsa_p->length, 2)));
        checksum_update(chksum, seckey_data->rsa_q->length, 2);
        checksum_update(chksum, seckey_data->rsa_q->value, 
                    bits2bytes( bytearr2uint(seckey_data->rsa_q->length, 2)));
        checksum_update(chksum, seckey_data->rsa_u->length, 2);
        checksum_update(chksum, seckey_data->rsa_u->value, 
                    bits2bytes( bytearr2uint(seckey_data->rsa_u->length, 2)));

        if (seckey_packet->s2k_usage == 0x00)
            file_write_bytes(fp, 2, seckey_data->hash);
        else // s2k_usage == 0xff
            file_write_bytes_encrypt(cipherctx, fp, 2, seckey_data->hash);

    } else if (seckey_packet->s2k_usage == 0xfe) {
        // 20 octet sha1 digest
        int r;
        ERR_load_crypto_strings();
        char error[400];

        unsigned char md[20];
        SHA_CTX shactx;
        r = SHA1_Init(&shactx);
        if(!r) {
            ERR_error_string(ERR_get_error(), error);
            printf("SHA1_Init failed %s\n",error);
        }

        SHA1_Update(&shactx, seckey_data->rsa_d->length, 2);
        SHA1_Update(&shactx, seckey_data->rsa_d->value, 
                bits2bytes( bytearr2uint(seckey_data->rsa_d->length, 2)));
        SHA1_Update(&shactx, seckey_data->rsa_p->length, 2);
        SHA1_Update(&shactx, seckey_data->rsa_p->value, 
                bits2bytes( bytearr2uint(seckey_data->rsa_p->length, 2)));
        SHA1_Update(&shactx, seckey_data->rsa_q->length, 2);
        SHA1_Update(&shactx, seckey_data->rsa_q->value, 
                bits2bytes( bytearr2uint(seckey_data->rsa_q->length, 2)));
        SHA1_Update(&shactx, seckey_data->rsa_u->length, 2);
        SHA1_Update(&shactx, seckey_data->rsa_u->value, 
                bits2bytes( bytearr2uint(seckey_data->rsa_u->length, 2)));
        SHA1_Final(md, &shactx);

        file_write_bytes_encrypt(cipherctx, fp, 20, seckey_data->hash);
    }
    pgp_cipher_finish(cipherctx);
}


int pgp_read_seckey_packet(FILE* fp, pgp_seckey_packet** seckey_packet)
{
    pgp_seckey_packet* seckey_pkt = (pgp_seckey_packet*)calloc(1, sizeof(pgp_seckey_packet));

    pgp_read_pubkey_packet(fp, &(seckey_pkt->pubkey_packet));
    seckey_pkt->s2k_usage = fgetc(fp);
    if ( seckey_pkt->s2k_usage == 0xff || 
         seckey_pkt->s2k_usage == 0xfe ) {
        file_read_bytes_alloc(fp, 1, &(seckey_pkt->enc_algo));
        pgp_read_s2k(fp, &(seckey_pkt->s2k));
    } else {
        seckey_pkt->enc_algo = &(seckey_pkt->s2k_usage);
        seckey_pkt->s2k = NULL;
    }

    if( seckey_pkt->s2k_usage != 0x00 )
        file_read_bytes_alloc(fp, get_block_size(seckey_pkt->enc_algo[0]), &(seckey_pkt->iv));
    else
        seckey_pkt->iv = NULL;

    // Derive key
    const char* passphrase = NULL;
    unsigned char* key = NULL;
    if (seckey_pkt->s2k_usage != 0x00) {
        passphrase = ask_passphrase();
        if ( seckey_pkt->s2k_usage == 0xff || 
             seckey_pkt->s2k_usage == 0xfe ) {
            pgp_derive_key(passphrase, seckey_pkt, &key);
        } else { // When no S2K exists, use MD5 to derive the key
            unsigned char md[HASH_MD5_HASH_SIZE];
            unsigned int key_size = get_hash_size(seckey_pkt->enc_algo[0]);
            MD5_CTX md5ctx;
            MD5_Init(&md5ctx);
            MD5_Update(&md5ctx, passphrase, strlen(passphrase));
            MD5_Final(md, &md5ctx);
            memcpy(key, md, key_size);
        }
    }

    pgp_read_seckey_data(fp, seckey_pkt, key);
    *seckey_packet = seckey_pkt;
}

int pgp_write_seckey_packet(FILE* fp, pgp_seckey_packet* seckey_pkt)
{
    int r;

    pgp_write_pubkey_packet(fp, seckey_pkt->pubkey_packet);
    r = fputc(seckey_pkt->s2k_usage, fp);

    if ( seckey_pkt->s2k_usage == 0xff || 
         seckey_pkt->s2k_usage == 0xfe ) {
        file_write_bytes(fp, 1, seckey_pkt->enc_algo);
        pgp_write_s2k(fp, seckey_pkt->s2k);
    } else {
        fputc(seckey_pkt->s2k_usage, fp);
    }

    if( seckey_pkt->s2k_usage != 0x00 )
        file_write_bytes(fp, get_block_size(seckey_pkt->enc_algo[0]), seckey_pkt->iv);

    // Derive key
    const char* passphrase = NULL;
    unsigned char* key = NULL;
    if (seckey_pkt->s2k_usage != 0x00) {
        passphrase = ask_passphrase();
        if ( seckey_pkt->s2k_usage == 0xff || 
             seckey_pkt->s2k_usage == 0xfe ) {
            pgp_derive_key(passphrase, seckey_pkt, &key);
        } else { // When no S2K exists, use MD5 to derive the key
            unsigned char md[HASH_MD5_HASH_SIZE];
            unsigned int key_size = get_hash_size(seckey_pkt->enc_algo[0]);
            MD5_CTX md5ctx;
            MD5_Init(&md5ctx);
            MD5_Update(&md5ctx, passphrase, strlen(passphrase));
            MD5_Final(md, &md5ctx);
            memcpy(key, md, key_size);
        }
    }

    pgp_write_seckey_data(fp, seckey_pkt, key);
}


int pgp_new_seckey_packet(RSA* rsa, unsigned char* passphrase, pgp_seckey_packet** pkt)
{
    ERR_load_crypto_strings();
    char error[400];

    pgp_seckey_packet* tmp_pkt = (pgp_seckey_packet*) malloc(sizeof(pgp_seckey_packet));

    tmp_pkt->s2k_usage = 0xfe;

    tmp_pkt->enc_algo = (unsigned char*)malloc(sizeof(unsigned char));
    tmp_pkt->enc_algo[0] = SYM_AES128; // aes-128

    tmp_pkt->s2k = (pgp_s2k*)malloc(sizeof(pgp_s2k));
    tmp_pkt->s2k->type = S2K_TYPE_ITERATED_SALTED; 
    tmp_pkt->s2k->hash_algo = HASH_SHA1;
    if(!RAND_bytes(tmp_pkt->s2k->salt, 8))
        RAND_pseudo_bytes(tmp_pkt->s2k->salt, 8);
// TODO: caclulate count, gnupg way
//    tmp_pkt->s2k->count = ;

    tmp_pkt->iv = (unsigned char*)malloc(sizeof(unsigned char) * SYM_AES128_BLOCK_SIZE);

    tmp_pkt->seckey_data = (pgp_seckey_data*) malloc(sizeof(pgp_seckey_data));

    BN_CTX* bnctx = BN_CTX_new();
    BIGNUM* rsa_u = BN_new();
    BN_mod_inverse(rsa_u, rsa->p, rsa->q, bnctx);
    if(rsa_u == NULL) {
        ERR_error_string(ERR_get_error(), error);
        printf("%s",error);
        return -1;
    }
    
    tmp_pkt->seckey_data->rsa_d = (pgp_mpi*)malloc(sizeof(pgp_mpi));
    tmp_pkt->seckey_data->rsa_p = (pgp_mpi*)malloc(sizeof(pgp_mpi));
    tmp_pkt->seckey_data->rsa_q = (pgp_mpi*)malloc(sizeof(pgp_mpi));
    tmp_pkt->seckey_data->rsa_u = (pgp_mpi*)malloc(sizeof(pgp_mpi));
    int d_len = BN_num_bytes(rsa->d);
    int p_len = BN_num_bytes(rsa->p);
    int q_len = BN_num_bytes(rsa->q);
    int u_len = BN_num_bytes(rsa_u);
    tmp_pkt->seckey_data->rsa_d->value = (unsigned char*) malloc(sizeof(unsigned char) * d_len);
    tmp_pkt->seckey_data->rsa_p->value = (unsigned char*) malloc(sizeof(unsigned char) * p_len);
    tmp_pkt->seckey_data->rsa_q->value = (unsigned char*) malloc(sizeof(unsigned char) * q_len);
    tmp_pkt->seckey_data->rsa_u->value = (unsigned char*) malloc(sizeof(unsigned char) * u_len);
    if (!BN_bn2bin(rsa->d, tmp_pkt->seckey_data->rsa_d->value)) {
        ERR_error_string(ERR_get_error(), error);
        printf("%s",error);
        return -1;
    }
    int2bytearr2(BN_num_bits(rsa->d), tmp_pkt->seckey_data->rsa_d->length);
    if(!BN_bn2bin(rsa->p, tmp_pkt->seckey_data->rsa_p->value)) {
        ERR_error_string(ERR_get_error(), error);
        printf("%s",error);
        return -1;
    }
    int2bytearr2(BN_num_bits(rsa->p), tmp_pkt->seckey_data->rsa_p->length);
    if(!BN_bn2bin(rsa->q, tmp_pkt->seckey_data->rsa_q->value)) {
        ERR_error_string(ERR_get_error(), error);
        printf("%s",error);
        return -1;
    }
    int2bytearr2(BN_num_bits(rsa->q), tmp_pkt->seckey_data->rsa_q->length);
    if(!BN_bn2bin(rsa_u, tmp_pkt->seckey_data->rsa_u->value)) {
        ERR_error_string(ERR_get_error(), error);
        printf("%s",error);
        return -1;
    }
    int2bytearr2(BN_num_bits(rsa_u), tmp_pkt->seckey_data->rsa_u->length);

    // TODO: calculate sha-1 hash
    tmp_pkt->seckey_data->hash = (unsigned char*) malloc(sizeof(unsigned char)*HASH_SHA1_HASH_SIZE);
    
    *pkt = tmp_pkt;
}

/*
 * Reads a packet from file @fp,
 * Stores the packet to the fresh-allocated @pgp_packet, 
 * and it's header to fresh-allocated @hdr
 */
int pgp_read_packet(FILE* fp, void** pgp_packet, pgp_packet_header** hdr)
{
    int i;
    pgp_packet_header* tmp_hdr = (pgp_packet_header*) calloc(1, sizeof(pgp_packet_header));
    
    // Header Tag
    unsigned char ptag;
    ptag = fgetc(fp);
    if ( !VALIDATE_TAG(ptag) ) {
        printf("Not a packet header\n");
        return -1;
    }
    tmp_hdr->ptag = ptag;
    unsigned int old_packet = IS_OLD_FORMAT(tmp_hdr->ptag);

    unsigned int length_len;
    if (old_packet) {
        length_len = CALC_LENGTH_LEN (tmp_hdr->ptag);
        file_read_bytes_alloc(fp, length_len, &(tmp_hdr->length));
    } else { // New packet format
        unsigned char len_octet_1 = fgetc(fp);
        if (len_octet_1 < 192) {
            length_len = 1;
        } else if (len_octet_1 <= 223) {
            length_len = 2;
        } else if (len_octet_1 == 0xff) {
            length_len = 5;
        } else {
            printf("Invalid length field for new pakcet format\n");
            return -1;
        }
        tmp_hdr->length = (unsigned char*)calloc(length_len, sizeof(unsigned char));
        tmp_hdr->length[0] = len_octet_1;
        file_read_bytes(fp, length_len-1, &(tmp_hdr->length[1]));
    }

    print_bytearr("Packet length", tmp_hdr->length, 4);

    if ( IS_PUB_KEY_PACKET(tmp_hdr->ptag)) {
        pgp_pubkey_packet* pub_packet;
        pgp_read_pubkey_packet(fp, &pub_packet);
        *pgp_packet = (void*)pub_packet;
    }

    if ( IS_SECRET_KEY_PACKET(tmp_hdr->ptag) ) {
        pgp_seckey_packet* sec_packet;
        pgp_read_seckey_packet(fp, &sec_packet);
        *pgp_packet = (void*)sec_packet;
    }

    *hdr = tmp_hdr;
    return 0;
}


// TODO:
int pgp_write_packet(FILE* fp, void* pgp_packet, pgp_packet_header* hdr)
{
    int i,r;
    pgp_packet_header* tmp_hdr = (pgp_packet_header*) calloc(1, sizeof(pgp_packet_header));
    
    // Header Tag
    unsigned char ptag;
    r = fputc(ptag, fp);
    if ( !VALIDATE_TAG(ptag) ) {
        printf("Not a packet header\n");
        return -1;
    }
    tmp_hdr->ptag = ptag;
    unsigned int old_packet = IS_OLD_FORMAT(tmp_hdr->ptag);

    unsigned int length_len;
    if (old_packet) {
        length_len = CALC_LENGTH_LEN (tmp_hdr->ptag);
        file_read_bytes_alloc(fp, length_len, &(tmp_hdr->length));
    } else { // New packet format
        unsigned char len_octet_1 = fgetc(fp);
        if (len_octet_1 < 192) {
            length_len = 1;
        } else if (len_octet_1 <= 223) {
            length_len = 2;
        } else if (len_octet_1 == 0xff) {
            length_len = 5;
        } else {
            printf("Invalid length field for new pakcet format\n");
            return -1;
        }
        tmp_hdr->length = (unsigned char*)calloc(length_len, sizeof(unsigned char));
        tmp_hdr->length[0] = len_octet_1;
        file_read_bytes(fp, length_len-1, &(tmp_hdr->length[1]));
    }

    print_bytearr("Packet length", tmp_hdr->length, 4);

    if ( IS_PUB_KEY_PACKET(tmp_hdr->ptag)) {
        pgp_pubkey_packet* pub_packet;
        pgp_read_pubkey_packet(fp, &pub_packet);
    }

    if ( IS_SECRET_KEY_PACKET(tmp_hdr->ptag) ) {
        pgp_seckey_packet* sec_packet;
        pgp_read_seckey_packet(fp, &sec_packet);
    }

    return 0;
}


/*
 * Reads an OpenPGP message from file at @filepath
 * Returns the message to the pre-allocated @msg
 */
int pgp_read_msg_file(const char* filepath, pgp_message* msg)
{
    FILE* fp = fopen(filepath,"r");
    if(!fp) {
        perror("Error");
        return -1;
    }

    // TODO:
    // read ALL packets belonging to a message
    // do {
    void* pgp_packet;
    pgp_packet_header* hdr;
    pgp_read_packet(fp, &pgp_packet, &hdr);
    msg->packet_type = GET_TAG(hdr->ptag);
    msg->pgp_packet = pgp_packet;
    msg->next = NULL;
    // while()
   
    fclose(fp);
    return 0;
}

// TODO:
int pgp_write_msg_file(const char* filepath, pgp_message* msg)
{
    FILE* fp = fopen(filepath,"r");
    if(!fp) {
        perror("Error");
        return -1;
    }

    // TODO:
    // write ALL packets belonging to a message
    // do {
    void* pgp_packet = msg->pgp_packet;
    // TODO: construct header
    pgp_packet_header* hdr;// = msg->;
    pgp_write_packet(fp, pgp_packet, hdr);
    // while()
   
    fclose(fp);
    return 0;
}
