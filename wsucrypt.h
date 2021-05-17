#ifndef WSUCRYPT_H
#define WSUCRYPT_H
#include <stdbool.h>

// encodes plaintext to HEX with the twofish algorithm
int encode( int  (*readFunc )(void* context),
            int  (*readKeyFunc )(void* context),
            void (*writeFunc)(unsigned char c, void* context),
            void* context);

// decodes HEX to plaintext with the twofish algorithm
int decode( int  (*readFunc )(void* context),
            int  (*readKeyFunc )(void* context),
            void (*writeFunc)(unsigned char c, void* context),
            void* context);

#endif
