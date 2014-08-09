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
        printf("%d\n",byte_arr[i]);
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

void pgp_print_pubkey_packet(pgp_pubkey_packet* pgp_packet)
{
    printf("Version: %.2x\n", pgp_packet->version);
    print_bytearr("Time", pgp_packet->creation_time, 4);
    printf("Algorithm: %d\n", pgp_packet->algo);
    // TODO: get modulus length
    print_mpi("Modulus", pgp_packet->modulus);
    print_mpi("Exponent", pgp_packet->exponent);
}

int pgp_read_mpi(FILE* fp, pgp_mpi** mpi)
{
    int r;
    pgp_mpi* tmp_mpi = (pgp_mpi*)calloc(1, sizeof(pgp_mpi));
    r = file_read_bytes(fp, 2, tmp_mpi->length);
    if(r != 0)
        return r;

    unsigned int value_len = bits2bytes( bytearr2uint(tmp_mpi->length, 2)); //bytes
    printf("value_len = %d\n", value_len);
    r = file_read_bytes_alloc(fp, value_len, &(tmp_mpi->value));
    if(r != 0)
        return r;
    *mpi = tmp_mpi;
    return 0;
}


int pgp_read_pubkey_packet(FILE* fp, pgp_pubkey_packet** pubkey_packet)
{
    int i;
    // TODO: calc (or get from parameter) modulus length
    unsigned int modulus_length = 256;
    pgp_pubkey_packet* pubkey_pkt = (pgp_pubkey_packet*) calloc(1, sizeof(pgp_pubkey_packet));

    // TODO: Read version 3
    pubkey_pkt->version = fgetc(fp);
    file_read_bytes(fp, 4, pubkey_pkt->creation_time);
    pubkey_pkt->algo = fgetc(fp);
    pgp_read_mpi(fp, &(pubkey_pkt->modulus));
    pgp_read_mpi(fp, &(pubkey_pkt->exponent));

    *pubkey_packet = pubkey_pkt;
    return 0;
}



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

    // TODO: convert packet length to int
    unsigned int length_len;
    if (old_packet) {
        length_len = CALC_LENGTH_LEN (tmp_hdr->ptag);
        tmp_hdr->length = (unsigned char*) calloc(1, sizeof(unsigned char*));
        for(i=0; i<length_len; i++) {
            tmp_hdr->length[i] = fgetc(fp);
        }
    } else { // New packet format
    }

    if ( IS_PUB_KEY_PACKET(tmp_hdr->ptag)) {
        pgp_pubkey_packet* pub_packet;
        pgp_read_pubkey_packet(fp, &pub_packet);
        *pgp_packet = (void*)pub_packet;
    }

    // TODO: read secret key packet fields
    if ( IS_SECRET_KEY_PACKET(tmp_hdr->ptag) ) {
    }

    *hdr = tmp_hdr;
    return 0;
}

int pgp_read_msg_file(const char* filepath, pgp_message* msg)
{
    FILE* fp = fopen(filepath,"r");
    if(!fp) {
        perror("Error");
        return -1;
    }

    // TODO:
    // read ALL packets belonging to a message
    void* pgp_packet;
    pgp_packet_header* hdr;
    pgp_read_packet(fp, &pgp_packet, &hdr);
    msg->packet_type = GET_TAG(hdr->ptag);
    msg->pgp_packet = pgp_packet;
    msg->next = NULL;

    
    fclose(fp);
    return 0;
}
