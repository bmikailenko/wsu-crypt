#ifndef BITSTREAM_H
#define BITSTREAM_H
#include <stdbool.h>

#define MAX_CODE_BITS   24
#define CHAR_BITS       8

/* BitStream: module to enable variable width integers/codes to be read */
/* or written from/to an open stdio FILE* */

/* module only supports codes with 8 to 24 bit width */

typedef struct _bitStream {
    int (*readFunc)(void* context);
    void (*writeFunc)(unsigned char c, void* context);
    void* context;
    int direction;              // input or output
    char block[8];              // 64 bit (8 byte) block
} BitStream;

BitStream* openInputBitStream(int (*readFunc)(void* context), void* context);

BitStream* openKeyBitStream(int (*readFunc)(void* context), void* context);

BitStream* openOutputBitStream(void (*writeFunc)(unsigned char c, void* context), void* context);

// output bits represented in binary to HEX
void outputBits_HEX(BitStream* bs, int *sequence);

// output bits represented in binary to plaintext
void outputBits_plaintext(BitStream* bs, int *sequence);

// read in bits from bitstream
int readInBits(BitStream* bs, unsigned int nBits);

#endif
