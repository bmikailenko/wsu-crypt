#include <stdlib.h>
#include <bitStream.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

BitStream* openInputBitStream(int (*readFunc)(void* context), void* context) {
  BitStream* tempBitStream = malloc(sizeof(BitStream));

  tempBitStream->readFunc = readFunc;
  tempBitStream->context = context;
  tempBitStream->direction = 1;

  return tempBitStream;
}

BitStream* openKeyBitStream(int (*readFunc)(void* context), void* context) {
  BitStream* tempBitStream = malloc(sizeof(BitStream));

  tempBitStream->readFunc = readFunc;
  tempBitStream->context = context;
  tempBitStream->direction = 1;

  return tempBitStream;
}

BitStream* openOutputBitStream(void (*writeFunc)(unsigned char c,void* context),void* context) {
  BitStream* tempBitStream = malloc(sizeof(BitStream));

  tempBitStream->writeFunc = writeFunc;
  tempBitStream->context = context;
  tempBitStream->direction = 0;

  return tempBitStream;
}

// output bits represented in binary to HEX
void outputBits_HEX(BitStream* bs, int *sequence) {
  unsigned char c;
  int n;

  for (int j = 0; j < 16; j++) { // for each of 16 HEX values

    n = 0;

    // calculate hex value 
    n += sequence[(j*4) + 3];
    n += sequence[(j*4) + 2] * 2;
    n += sequence[(j*4) + 1] * 4;
    n += sequence[(j*4)] * 8;

    // write the hex value to ouput
    if (n == 0)
      bs->writeFunc('0', bs->context); 
    if (n == 1)
      bs->writeFunc('1', bs->context); 
    if (n == 2)
      bs->writeFunc('2', bs->context);
    if (n == 3)
      bs->writeFunc('3', bs->context);
    if (n == 4)
      bs->writeFunc('4', bs->context);
    if (n == 5)
      bs->writeFunc('5', bs->context);
    if (n == 6)
      bs->writeFunc('6', bs->context);
    if (n == 7)
      bs->writeFunc('7', bs->context);
    if (n == 8)
      bs->writeFunc('8', bs->context);
    if (n == 9)
      bs->writeFunc('9', bs->context);
    if (n == 10)
      bs->writeFunc('a', bs->context);
    if (n == 11)
      bs->writeFunc('b', bs->context);
    if (n == 12)
      bs->writeFunc('c', bs->context);
    if (n == 13)
      bs->writeFunc('d', bs->context);
    if (n == 14)
      bs->writeFunc('e', bs->context);
    if (n == 15)
      bs->writeFunc('f', bs->context);
  }
  return;
}

// output bits represented in binary to plaintext
void outputBits_plaintext(BitStream* bs, int *sequence) {
  unsigned char c;
  int n;

  for (int j = 0; j < 8; j++) { // for each of byte 

    n = 1; // multiplier
    c = 0; // char

    for (int i = 7; i >= 0; i--) { // for each bit
      c += sequence[(j*8)+i] * n; // convert to decimal
      n *= 2;
    }
    bs->writeFunc(c, bs->context); // write char to output from decimal value
  }
  return;
}

/* Read an nBit code from fileStream, if EOF, return -1,
else write the code to the pointer argument */
int readInBits(BitStream* bs, unsigned int nBits) {
  int read, bitsRead = 0, i = 0, flag = 0;

  while (bitsRead < nBits) {
    read = bs->readFunc(bs->context);         // read in 8 bits

    if (read < 0 && bitsRead == 0)
      return -1; // first 8 bits read was EOF

    if (read < 0) { // input was not a multiple of 64 bits or 8 bytes
      read = 48; // ASCII decimal value of "0"
      flag = 1; 
      while (bitsRead < nBits) {
        bs->block[i] = read; // pad with zeros
        i++;
        bitsRead += 8;
      }
    } 
    
    else {
      bs->block[i] = read;
      bitsRead += 8;
      i++;
    }

  }

  return flag;

}
