#include <openssl/evp.h>
#include <openssl/err.h>

#include "openpgp-msg.h"

static
const char* ask_passphrase()
{
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
        // Hash 'count' octets of 
        // [ (salt || passphrase) || (salt || passphrase) || ... ]
        for( i=0; i<s2k->count; i+= get_hash_size(s2k->hash_algo) ) {
            EVP_DigestUpdate(mdctx, s2k->salt, strlen( (const char*)s2k->salt));
            EVP_DigestUpdate(mdctx, passphrase, strlen(passphrase));
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
void pgp_derive_key(const char* passphrase, pgp_seckey_packet* pkt, unsigned char** key)
{
    int i;

    int key_size = get_key_size(pkt->enc_algo[0]);
    *key = (unsigned char*) calloc(key_size, sizeof(unsigned char) );
    
    int hash_size = get_hash_size(pkt->s2k->hash_algo);
    unsigned char* hash;

    if (hash_size >= key_size) {
        // Hash once and truncate if necessary
        pgp_hash(passphrase, NULL,  pkt->s2k, &hash);
        memcpy(key, hash, key_size);
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
}


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

/*
 * Read secret key packet data from file @fp
 * Decrypt if necessary using @keya
 * Returns updated @seckey_packet
 */
static
int pgp_read_seckey_data(FILE* fp, pgp_seckey_packet* seckey_packet, unsigned char* key)
{
// TODO: Decrypt as a stream
    seckey_packet->seckey_data = (pgp_seckey_data*)calloc(1, sizeof(pgp_seckey_data));

    if(seckey_packet->s2k_usage == 0x00) { // Plain
        file_read_bytes_alloc(fp, 20, &(seckey_packet->seckey_data->hash));
        pgp_read_mpi(fp, &(seckey_packet->seckey_data->rsa_d));
        pgp_read_mpi(fp, &(seckey_packet->seckey_data->rsa_p));
        pgp_read_mpi(fp, &(seckey_packet->seckey_data->rsa_q));
        pgp_read_mpi(fp, &(seckey_packet->seckey_data->rsa_u));
    } else {
        if (seckey_packet->s2k_usage == 0xfe)
            
        if (seckey_packet->s2k_usage == 0xff)
            
    } else { // TODO: No S2K
    }

/*
    if (seckey_packet->s2k_usage == 0xfe || seckey_packet->s2k_usage == 0x00)
        file_read_bytes_alloc(fp, 20, &(seckey_packet->seckey_data->hash));
    else 
        file_read_bytes_alloc(fp, 2, &(seckey_packet->seckey_data->hash));

*/

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
        pgp_derive_key(passphrase, seckey_pkt, &key);
    }

    pgp_read_seckey_data(fp, seckey_pkt, key);
    *seckey_packet = seckey_pkt;
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
