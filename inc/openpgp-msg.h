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


/*----------- Errors ---------*/
#define FILE_READ_BYTES_PREMATURE_EOF   -1
/*------------------ ---------*/


/*---------- Data Element Format ------------*/
typedef struct _pgp_mpi {
    unsigned char length[2]; // In bits
    unsigned char* value;
}pgp_mpi;
/*-------------------------------------------*/


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
    unsigned char algo;

    pgp_mpi* modulus;
    pgp_mpi* exponent;
}pgp_pubkey_packet;
/*----------------------------------------*/

void pgp_print_pubkey_packet(pgp_pubkey_packet* pgp_packet);
int pgp_read_pubkey_packet(FILE* fp, pgp_pubkey_packet** pubkey_packet);
int pgp_read_packet(FILE* fp, void** pgp_packet, pgp_packet_header** hdr);
int pgp_read_msg_file(const char* filepath, pgp_message* msg);

#endif // OPENPGP_MSG_H
