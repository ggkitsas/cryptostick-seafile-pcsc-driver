#ifndef OPENPGP_MSG_H
#define OPENPGP_MSG_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>


/*------------- PTag utilities ------------*/
#define VALIDATE_TAG(tag) (((tag) & 0x80) == 0x80 ? 1:0)
#define IS_OLD_FORMAT(tag) (((tag) & 0x40) == 0x00 ? 1:0)

/*   length   */
#define OLD_FORMAT_GET_TAG(tag) ((tag) & OLD_FORMAT_TAG_MASK)
#define NEW_FORMAT_GET_TAG(tag) ((tag) & NEW_FORMAT_TAG_MASK)
#define OLD_FORMAT_GET_LENGTH_TYPE(tag) ((tag) & 0x03)
#define ONE_OCTET_LENGTH            0x00
#define TWO_OCTET_LENGTH            0x01
#define FIVE_OCTET_LENGTH           0x02
#define INDETERMINATE_OCTET_LENGTH  0x03

#define CALC_LENGTH_LEN(tag)           \
                (IS_OLD_FORMAT((tag)) ? \
                (OLD_FORMAT_GET_LENGTH_TYPE((tag)) == ONE_OCTET_LENGTH ? 1 : \
                (OLD_FORMAT_GET_LENGTH_TYPE((tag)) == TWO_OCTET_LENGTH ? 2 : \
                (OLD_FORMAT_GET_LENGTH_TYPE((tag)) == FIVE_OCTET_LENGTH ? 5 : 0))) : 0)

/*   tag   */
#define OLD_FORMAT_TAG_MASK 0x3c
#define NEW_FORMAT_TAG_MASK 0x3f
// old format
#define RESERVED_TAG                0x00
#define PUBKEY_ENC_SESSION_KEY_TAG  0x01
#define SIGNATURE_TAG               0x02
#define SYM_KEY_ENC_SESSION_KEY_TAG 0x03
#define ONE_PASS_SIG_TAG            0x04
#define SECRET_KEY_TAG              0x05
#define PUBLIC_KEY_TAG              0x06
#define SECRET_SUBKEY_TAG           0x07
#define COMPRESSED_DATA_TAG         0x08
#define SYM_ENC_DATA_TAG            0x09
#define MARKER_TAG                  0x10
#define LITERAL_DATA_TAG            0x11
#define TRUST_TAG                   0x12
#define USER_ID_TAG                 0x13
#define PUBLIC_SUBKEY_TAG           0x14
// new format
#define USER_ATTR_TAG               0x17
#define SYM_ENC_INTEG_DATA_TAG      0x18
#define MODIF_DETECT_CODE_TAG       0x19

#define GET_OLD_FORMAT_TAG(tag) ( ((tag) & OLD_FORMAT_TAG_MASK) >> 2)
#define GET_NEW_FORMAT_TAG(tag) ((tag) & NEW_FORMAT_TAG_MASK)
#define GET_TAG(tag) (IS_OLD_FORMAT((tag)) ? GET_OLD_FORMAT_TAG((tag)) : GET_NEW_FORMAT_TAG((tag)))

#define IS_PUB_KEY_PACKET(tag) (GET_TAG((tag)) == PUBLIC_KEY_TAG || GET_TAG((tag)) == PUBLIC_SUBKEY_TAG ? 1:0)
#define IS_SECRET_KEY_PACKET(tag) (GET_TAG((tag)) == SECRET_KEY_TAG || GET_TAG((tag)) == SECRET_SUBKEY_TAG ? 1:0)

/*----------------- String to Key  ------------------*/
#define S2K_TYPE_SIMPLE              0x00
#define S2K_TYPE_SALTED              0x01
#define S2K_TYPE_ITERATED_SALTED     0x03
#define S2K_TYPE_GNUPG               101  // gnupg extension
/*-------------------------------- ------------------*/

/*---------------- Algorithms  -----------------*/
// Hash algos
#define HASH_MD5         1
#define HASH_SHA1        2
#define HASH_RIPEMD160   3
#define HASH_SHA256      8
#define HASH_SHA384      9
#define HASH_SHA512      10
#define HASH_SHA224      11

#define HASH_MD5_HASH_SIZE         16
#define HASH_SHA1_HASH_SIZE        20
#define HASH_RIPEMD160_HASH_SIZE   20
#define HASH_SHA256_HASH_SIZE      32
#define HASH_SHA384_HASH_SIZE      48
#define HASH_SHA512_HASH_SIZE      64
#define HASH_SHA224_HASH_SIZE      28

inline
unsigned int get_hash_size(unsigned char hash_algo)
{
    switch(hash_algo) {
        case HASH_MD5:
            return HASH_MD5_HASH_SIZE;
        case HASH_SHA1:
        case HASH_RIPEMD160:
            return HASH_SHA1_HASH_SIZE;
        case HASH_SHA256:
            return HASH_SHA256_HASH_SIZE;
        case HASH_SHA384:
            return HASH_SHA384_HASH_SIZE;
        case HASH_SHA512:
            return HASH_SHA512_HASH_SIZE;
        case HASH_SHA224:
            return HASH_SHA224_HASH_SIZE;
        default:
            printf("Error: Unsupported hash algorithm\n");
            return 0; 
    }
}

inline
const char* get_hash_name(unsigned char hash_algo)
{
     switch(hash_algo) {
        case HASH_MD5:
            return "md5";
        case HASH_SHA1:
            return "sha1";
        case HASH_RIPEMD160:
            return "ripemd160";
        case HASH_SHA256:
            return "sha256";
        case HASH_SHA384:
            return "sha384";
        case HASH_SHA512:
            return "sha512";
        case HASH_SHA224:
            return "sha224";
        default:
            printf("Error: Unsupported hash algorithm\n");
            return NULL;
    }
}

// Public key algos
#define PUB_RSA_ENC_SIG 1
#define PUB_RSA_ENC     2
#define PUB_RSA_SIG     3
#define PUB_ELGAMAL_ENC 16
#define PUB_DSA         17

// Symmetric encryption
#define SYM_PLAINTEXT   0
#define SYM_IDEA        1
#define SYM_TRIPLEDES   2
#define SYM_CAST5       3
#define SYM_BLOWFISH    4
#define SYM_AES128      7
#define SYM_AES192      8
#define SYM_AES256      9
#define SYM_TWOFISH256  10

#define SYM_IDEA_BLOCK_SIZE        8
#define SYM_TRIPLEDES_BLOCK_SIZE   8
#define SYM_CAST5_BLOCK_SIZE       8
#define SYM_BLOWFISH_BLOCK_SIZE    8
#define SYM_AES128_BLOCK_SIZE      16
#define SYM_AES192_BLOCK_SIZE      16
#define SYM_AES256_BLOCK_SIZE      16
#define SYM_TWOFISH256_BLOCK_SIZE  16

#define SYM_IDEA_KEY_SIZE        16
#define SYM_TRIPLEDES_KEY_SIZE   21 // Out of 24
#define SYM_CAST5_KEY_SIZE       16
#define SYM_BLOWFISH_KEY_SIZE    16
#define SYM_AES128_KEY_SIZE      16
#define SYM_AES192_KEY_SIZE      24
#define SYM_AES256_KEY_SIZE      32
#define SYM_TWOFISH256_KEY_SIZE  32

inline
unsigned int get_block_size(unsigned char sym_algo)
{
    switch(sym_algo) {
        case SYM_IDEA:
        case SYM_TRIPLEDES:
        case SYM_CAST5:
        case SYM_BLOWFISH:
            return SYM_IDEA_BLOCK_SIZE;
        case SYM_AES128:
        case SYM_AES192:
        case SYM_AES256:
        case SYM_TWOFISH256:
            return SYM_AES128_BLOCK_SIZE;
        default:
            printf("Error: Unsupported symmetric encryption algorithm\n");
            return 0;
    }
}

inline
unsigned int get_key_size(unsigned char sym_algo)
{
    switch(sym_algo){
        case SYM_IDEA:
        case SYM_CAST5:
        case SYM_BLOWFISH:
        case SYM_AES128:
            return SYM_IDEA_KEY_SIZE;
        case SYM_TRIPLEDES:
            return SYM_TRIPLEDES_KEY_SIZE;
        case SYM_AES192:
            return SYM_AES192_KEY_SIZE;
        case SYM_AES256:
        case SYM_TWOFISH256:
            return SYM_AES256_KEY_SIZE;
        default:
            printf("Error: Unsupported symmetric encryption algorithm\n");
            return 0;
    }
}

inline
const char* get_cipher_name(unsigned char cipher_algo)
{
    switch(cipher_algo) {
        case SYM_IDEA:
            return "idea-cfb";
        case SYM_CAST5:
            return "cast-cfb";
        case SYM_BLOWFISH:
            return "bf-cfb";
        case SYM_AES128:
            return "aes-128-cfb";
        case SYM_TRIPLEDES:
            return "des-ede3-cfb";
        case SYM_AES192:
            return "aes-192-cfb";
        case SYM_AES256:
            return "aes-256-cfb";
        case SYM_TWOFISH256: // Not available in OpenSSL
        default:
            printf("Error: Unsupported symmetric encryption algorithm\n");
            return 0;
    }
} 
/*--------------------------------------------------*/

/*----------- Errors ---------*/
#define FILE_READ_BYTES_PREMATURE_EOF   -1

#define UNSUPPROTED_S2K     -1
/*------------------ ---------*/


/*---------- Data Elements ------------*/
typedef struct _pgp_mpi {
    unsigned char length[2]; // In bits
    unsigned char* value;
}pgp_mpi;

typedef struct _pgp_s2k {
    unsigned char type;
    unsigned char hash_algo;
    unsigned char salt[8];
    unsigned char count;
}pgp_s2k;
/*-------------------------------------*/


typedef struct _pgp_message {
    int packet_type;
    void* pgp_packet;
    
    struct _pgp_message* next;
}pgp_message;


/*----------- Packet structures -----------*/
typedef struct _pgp_packet_header {
    unsigned char ptag;
    unsigned char* length;
}pgp_packet_header;

typedef struct _pgp_pubkey_packet {
    unsigned char version;
    unsigned char creation_time[4];
    unsigned char* validity_period; // V3 pubkey packet, 
                                    // 2 byte long,
                                    // use pointer to encode it's absence with NULL
    unsigned char algo;

    pgp_mpi* modulus;
    pgp_mpi* exponent;
}pgp_pubkey_packet;

typedef struct _pgp_seckey_data {
    unsigned char* hash; // SHA1-hash or checksum, depending of s2k_usage

    pgp_mpi* rsa_d;
    pgp_mpi* rsa_p;
    pgp_mpi* rsa_q;
    pgp_mpi* rsa_u;
}pgp_seckey_data;

typedef struct _pgp_seckey_packet {
    pgp_pubkey_packet* pubkey_packet;

    unsigned char s2k_usage;
    unsigned char* enc_algo;
    pgp_s2k* s2k;
    unsigned char* iv;

    pgp_seckey_data* seckey_data;
}pgp_seckey_packet;
/*----------------------------------------*/

void pgp_print_pubkey_packet(pgp_pubkey_packet* pgp_packet);
void pgp_print_seckey_packet(pgp_seckey_packet* pkt);
int pgp_read_pubkey_packet(FILE* fp, pgp_pubkey_packet** pubkey_packet);
int pgp_read_packet(FILE* fp, void** pgp_packet, pgp_packet_header** hdr);
int pgp_read_msg_file(const char* filepath, pgp_message* msg);

#endif // OPENPGP_MSG_H
