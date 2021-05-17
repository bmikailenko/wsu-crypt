// Ben Mikailenko

#include <bitStream.h>
#include <wsucrypt.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <math.h>

static const unsigned char ftable[16][16] = { 
	{0xa3,0xd7,0x09,0x83,0xf8,0x48,0xf6,0xf4,0xb3,0x21,0x15,0x78,0x99,0xb1,0xaf,0xf9},
	{0xe7,0x2d,0x4d,0x8a,0xce,0x4c,0xca,0x2e,0x52,0x95,0xd9,0x1e,0x4e,0x38,0x44,0x28},
	{0x0a,0xdf,0x02,0xa0,0x17,0xf1,0x60,0x68,0x12,0xb7,0x7a,0xc3,0xe9,0xfa,0x3d,0x53},
	{0x96,0x84,0x6b,0xba,0xf2,0x63,0x9a,0x19,0x7c,0xae,0xe5,0xf5,0xf7,0x16,0x6a,0xa2},
	{0x39,0xb6,0x7b,0x0f,0xc1,0x93,0x81,0x1b,0xee,0xb4,0x1a,0xea,0xd0,0x91,0x2f,0xb8},
	{0x55,0xb9,0xda,0x85,0x3f,0x41,0xbf,0xe0,0x5a,0x58,0x80,0x5f,0x66,0x0b,0xd8,0x90},
	{0x35,0xd5,0xc0,0xa7,0x33,0x06,0x65,0x69,0x45,0x00,0x94,0x56,0x6d,0x98,0x9b,0x76},
	{0x97,0xfc,0xb2,0xc2,0xb0,0xfe,0xdb,0x20,0xe1,0xeb,0xd6,0xe4,0xdd,0x47,0x4a,0x1d},
	{0x42,0xed,0x9e,0x6e,0x49,0x3c,0xcd,0x43,0x27,0xd2,0x07,0xd4,0xde,0xc7,0x67,0x18},
	{0x89,0xcb,0x30,0x1f,0x8d,0xc6,0x8f,0xaa,0xc8,0x74,0xdc,0xc9,0x5d,0x5c,0x31,0xa4},
	{0x70,0x88,0x61,0x2c,0x9f,0x0d,0x2b,0x87,0x50,0x82,0x54,0x64,0x26,0x7d,0x03,0x40},
	{0x34,0x4b,0x1c,0x73,0xd1,0xc4,0xfd,0x3b,0xcc,0xfb,0x7f,0xab,0xe6,0x3e,0x5b,0xa5},
	{0xad,0x04,0x23,0x9c,0x14,0x51,0x22,0xf0,0x29,0x79,0x71,0x7e,0xff,0x8c,0x0e,0xe2},
	{0x0c,0xef,0xbc,0x72,0x75,0x6f,0x37,0xa1,0xec,0xd3,0x8e,0x62,0x8b,0x86,0x10,0xe8},
	{0x08,0x77,0x11,0xbe,0x92,0x4f,0x24,0xc5,0x32,0x36,0x9d,0xcf,0xf3,0xa6,0xbb,0xac},
	{0x5e,0x6c,0xa9,0x13,0x57,0x25,0xb5,0xe3,0xbd,0xa8,0x3a,0x01,0x05,0x59,0x2a,0x46}
};

//  NOTE ON DEFINITIONS
// 
// Definitions for functions below are found in encode.c
//
static void copyBlock(char *src, int *dest, int size);
static bool copyBlock_HEX(char *src, int *dest, int size);
static void printBlock(int *block, int size);
static void XOR(int *input_1, int *input_2, int *output, int size);
static void leftRotate(int * sequence, int size);
static void rightRotate(int * sequence, int size);
static void K(int x, int *key_sequence, int *output);
static void G(int *w, int *k1, int *k2, int *k3, int *k4, int *output);
static void F(int *R_0, int *R_1, int *key_sequence, int round_number, int *output_F_0, int *output_F_1);
static void split_R(int *R_0, int *R_1, int *R_2, int *R_3, int *R);
static void f_table(int *bits, int *output);

//  add_binary
//  function converts three binary numbers represented
//    in an int array
//
//    note: we are storing our binary values in int arrays
//    ex: decimal (100) == binary (1100100) == stored as [1,1,0,0,1,0,0]
//
//     input: [binary int array, binary int array, binary int array]
//     output: integer of the three binary numbers added together
static int add_binary(int *b1, int *b2, int *b3);

int decode(   int (*readFunc)(void* context),
              int (*readKeyFunc)(void* context),
              void (*writeFunc)(unsigned char c, void* context),
              void* context) {
    BitStream* input = openInputBitStream(readFunc, context);
    BitStream* key = openKeyBitStream(readKeyFunc, context);
    BitStream* output = openOutputBitStream(writeFunc, context);
    int key_sequence[64];
    int input_sequence[64];
    int R_sequence[64];
    int R_0[16], R_1[16], R_2[16], R_3[16];
    int round_number, read_result;

    // read in the 64-bit long HEX key from the keyfile
    if (readInBits(key, 128) != 0) {

      // Error: 
      //  key length is less than 64-bits long
      printf("ERROR: key must be atleast 16 HEX characters long\n");
      printf("Ex: 'abcdef0123456789'\n");
      return 1;

    }

    // convert HEX key to binary and save into key_sequence[64] array as an int array
    if (copyBlock_HEX(key->block, key_sequence, 16) == false) {

      // Error: 
      //  key not in HEX alphabet (0-9, a-f, A-F)
      printf("ERROR: key must be in the HEX alphabet (0-9, a-f, A-F)\n");
      printf("Ex: 'abcdef0123456789'\n");
      return 1;

    }

    // while not at end of the file, decrypt
    while ((read_result = readInBits(input, 128)) == 0) {

      // convert HEX cipher code to binary and save into input_sequence[64] as an int array
      copyBlock_HEX(input->block, input_sequence, 16);	

      // whitening step
      XOR(key_sequence, input_sequence, R_sequence, 64);

      // split 64-bit output of whitening step into 4 16-bit words
      split_R(R_0, R_1, R_2, R_3, R_sequence);

      // return values from F() function calls
      int F_0[16], F_1[16];

      round_number = 0; // variable counts number of rounds the F() function is executed
      // perform 16 F() function rounds
      while (round_number != 16) {
        // perform F function on R_0 and R_1
        F(R_0, R_1, key_sequence, round_number, F_0, F_1);

        // temp values for R_0 and R_1 since we need them for R_2 and R_3
        int R_0_temp[16], R_1_temp[16];

        // copy R_0
        for (int i = 0; i < 16; i++)
          R_0_temp[i] = R_0[i];

        // copy R_1
        for (int i = 0; i < 16; i++)
          R_1_temp[i] = R_1[i];

        // compute the R_0 value for the next round
        leftRotate(R_2, 16);
        XOR(R_2, F_0, R_0, 16);

        // compute the R_1 value for the next round
        XOR(R_3, F_1, R_1, 16);
        rightRotate(R_1, 16);

        // copy R_0 to R_2
        for (int i = 0; i < 16; i++)
          R_2[i] = R_0_temp[i];

        // copy R_1 to R_3
        for (int i = 0; i < 16; i++)
          R_3[i] = R_1_temp[i];

        round_number += 1;
      }

      // undo the last swap
      int Y_0[16], Y_1[16], Y_2[16], Y_3[16];
      for (int i = 0; i < 16; i++) {
        Y_0[i] = R_2[i];
        Y_1[i] = R_3[i];
        Y_2[i] = R_0[i];
        Y_3[i] = R_1[i];
      }
          
      // consolidate into one array
      int Y[64];
      for (int i = 0; i < 16; i++)
        Y[i] = Y_0[i];
      for (int i = 0; i < 16; i++)
        Y[i+16] = Y_1[i];
      for (int i = 0; i < 16; i++)
        Y[i+32] = Y_2[i];
      for (int i = 0; i < 16; i++)
        Y[i+48] = Y_3[i];

      // output whitening step
      int C[64];
      XOR(Y, key_sequence, C, 64);

      // print the block to output
      outputBits_plaintext(output, C);  

    }

    if (read_result == 1) { // if theres a leftover unencrypted block, encrypt it

      printf("Warning: your ciphertext might be corrupted\n");
      printf("  invalid number (not multiple of 16) of HEX characters in input file\n");

    }

    return 0;

}

  void copyBlock(char *src, int *dest, int size) {
    int k = 0;
    for (int i = 0; i < size; i++) {
      for (int j = 0; j < 8; j++) {
        dest[k] = (!!((src[i] << j) & 0x80));
        k++;
      }
    }
  }

  bool copyBlock_HEX(char *src, int *dest, int size) {
    int k = 0;
    for (int i = 0; i < size; i++) {
      if (src[i] == '0') {
        dest[i * 4] = 0;
        dest[(i * 4)+1] = 0;
        dest[(i * 4)+2] = 0;
        dest[(i * 4)+3] = 0;
      }
      else if (src[i] == '1') {
        dest[i * 4] = 0;
        dest[(i * 4)+1] = 0;
        dest[(i * 4)+2] = 0;
        dest[(i * 4)+3] = 1;
      }
      else if (src[i] == '2') {
        dest[i * 4] = 0;
        dest[(i * 4)+1] = 0;
        dest[(i * 4)+2] = 1;
        dest[(i * 4)+3] = 0;
      }
      else if (src[i] == '3') {
        dest[i * 4] = 0;
        dest[(i * 4)+1] = 0;
        dest[(i * 4)+2] = 1;
        dest[(i * 4)+3] = 1;
      }
      else if (src[i] == '4') {
        dest[i * 4] = 0;
        dest[(i * 4)+1] = 1;
        dest[(i * 4)+2] = 0;
        dest[(i * 4)+3] = 0;
      }
      else if (src[i] == '5') {
        dest[i * 4] = 0;
        dest[(i * 4)+1] = 1;
        dest[(i * 4)+2] = 0;
        dest[(i * 4)+3] = 1;
      }
      else if (src[i] == '6') {
        dest[i * 4] = 0;
        dest[(i * 4)+1] = 1;
        dest[(i * 4)+2] = 1;
        dest[(i * 4)+3] = 0;
      }
      else if (src[i] == '7') {
        dest[i * 4] = 0;
        dest[(i * 4)+1] = 1;
        dest[(i * 4)+2] = 1;
        dest[(i * 4)+3] = 1;
      }
      else if (src[i] == '8') {
        dest[i * 4] = 1;
        dest[(i * 4)+1] = 0;
        dest[(i * 4)+2] = 0;
        dest[(i * 4)+3] = 0;
      }
      else if (src[i] == '9') {
        dest[i * 4] = 1;
        dest[(i * 4)+1] = 0;
        dest[(i * 4)+2] = 0;
        dest[(i * 4)+3] = 1;
      }
      else if (src[i] == 'a' || src[i] == 'A') {
        dest[i * 4] = 1;
        dest[(i * 4)+1] = 0;
        dest[(i * 4)+2] = 1;
        dest[(i * 4)+3] = 0;
      }
      else if (src[i] == 'b' || src[i] == 'B') {
        dest[i * 4] = 1;
        dest[(i * 4)+1] = 0;
        dest[(i * 4)+2] = 1;
        dest[(i * 4)+3] = 1;
      }
      else if (src[i] == 'c' || src[i] == 'C') {
        dest[i * 4] = 1;
        dest[(i * 4)+1] = 1;
        dest[(i * 4)+2] = 0;
        dest[(i * 4)+3] = 0;
      }
      else if (src[i] == 'd' || src[i] == 'D') {
        dest[i * 4] = 1;
        dest[(i * 4)+1] = 1;
        dest[(i * 4)+2] = 0;
        dest[(i * 4)+3] = 1;
      }
      else if (src[i] == 'e' || src[i] == 'E') {
        dest[i * 4] = 1;
        dest[(i * 4)+1] = 1;
        dest[(i * 4)+2] = 1;
        dest[(i * 4)+3] = 0;
      }
      else if (src[i] == 'f' || src[i] == 'F') {
        dest[i * 4] = 1;
        dest[(i * 4)+1] = 1;
        dest[(i * 4)+2] = 1;
        dest[(i * 4)+3] = 1;
      }
      else {
        return false;
      }
    }
    return true;
  }

  void K(int x, int *key_sequence, int *output) {
    for (int i = 0; i < 8; i++) 
      output[i] = key_sequence[((((x % 8) * 8)) + i)];
    rightRotate(key_sequence, 64);
    return;
  }

  void F(int *R_0, int *R_1, int *key_sequence, int round_number, int *output_F_0, int *output_F_1) {

    // keys for the G() function
    int gk_1[8], gk_2[8], gk_3[8], gk_4[8], gk_5[8], gk_6[8], gk_7[8], gk_8[8];

    // keys for the F() (this) function
    int fk_1[8], fk_2[8], fk_3[8], fk_4[8];

    // output of G() functions
    int T_0[16], T_1[16];

    // output of F() (this) function
    int F_0[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}, F_1[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

    // temp_array, T_1_x2, and T_0_x2 used for computing F_0 and F_1
    int temp_array[16], T_1_x2[17], T_0_x2[17];

    // n helps with converting decimal value F_decimal into F binary int array representation
    int n = 15;

    // computing keys for first call to G()
    K(4 * round_number, key_sequence, fk_4);
    K((4 * round_number) + 1, key_sequence, fk_3);
    K((4 * round_number) + 2, key_sequence, fk_2);
    K((4 * round_number) + 3, key_sequence, fk_1);

    // computing keys for second call to G()
    K(4 * round_number, key_sequence, gk_8);
    K((4 * round_number) + 1, key_sequence, gk_7);
    K((4 * round_number) + 2, key_sequence, gk_6);
    K((4 * round_number) + 3, key_sequence, gk_5);

    // computing keys for F_0 and F_1
    K(4 * round_number, key_sequence, gk_4);
    K((4 * round_number) + 1, key_sequence, gk_3);
    K((4 * round_number) + 2, key_sequence, gk_2);
    K((4 * round_number) + 3, key_sequence, gk_1);    


    // computing T_0
    G(R_0, gk_1, gk_2, gk_3, gk_4, T_0);

    // computing T_1
    G(R_1, gk_5, gk_6, gk_7, gk_8, T_1);

    //
    // getting F_0 = (T_0 + 2*T_1 + concatenate(fk_1, fk_2)) mod 2^16
    //
      // concat fk_1
    for (int i = 0; i < 8; i++)
      temp_array[i] = fk_1[i];

      // with fk_2 into temp_array
    for (int i = 0; i < 8; i++)
      temp_array[i+8] = fk_2[i];

      // 2 * T_1
    for (int i = 0; i < 16; i++)
      T_1_x2[i] = T_1[i];
    T_1_x2[16] = 0;

      // add the three binary numbers (T_0, T_1_x2, temp_array) into variable mod_value 
    int mod_value = add_binary(T_0, T_1_x2, temp_array);

      // get the decimal value of mod_value % 2^16
    int F_0_decimal = mod_value % ((int) pow(2, 16));

      // convert the decimal value of F_0_decimal into a binary value represented with an int array
    while (F_0_decimal > 0) {
      F_0[n] = F_0_decimal % 2;
      F_0_decimal = F_0_decimal / 2;
      n--;
    }

    //
    // getting F_1 = (2*T_0 + T_1 + concatenate(fk_3, fk_4)) mod 2^16
    //
      // concat fk_3
    for (int i = 0; i < 8; i++)
      temp_array[i] = fk_3[i];

      // with fk_4 into temp_array
    for (int i = 0; i < 8; i++)
      temp_array[i+8] = fk_4[i];

      // 2 * T_0
    for (int i = 0; i < 16; i++)
      T_0_x2[i] = T_0[i];
    T_0_x2[16] = 0;

      // add the three binary numbers (T_0, T_1_x2, temp_array) into variable mod_value 
    mod_value = add_binary(T_1, T_0_x2, temp_array);

      // get the decimal value of mod_value % 2^16
    int F_1_decimal = mod_value % ((int) pow(2, 16));

    n = 15; // reset n

      // convert the decimal value of F_0_decimal into a binary value represented with an int array
    while (F_1_decimal > 0) {
      F_1[n] = F_1_decimal % 2;
      F_1_decimal = F_1_decimal / 2;
      n--;
    }

    // copy F_0 to output output_F_0 that was passed in
    for (int i = 0; i < 16; i++)
      output_F_0[i] = F_0[i];

    // copy F_1 to output output_F_1 that was passed in
    for (int i = 0; i < 16; i++)
      output_F_1[i] = F_1[i];

    return;
  }

  void G(int *w, int *k1, int *k2, int *k3, int *k4, int *output) {
    int g_1[8], g_2[8], g_3[8], g_4[8], g_5[8], g_6[8];
    int temp_array[8], fvalue[8];

    // get g_1 = the left (high) 8 bits of w
    for (int i = 0; i < 8; i++)
      g_1[i] = w[i];

    // get g_2 = the right (low) 8 bits of w
    for (int i = 0; i < 8; i++)
      g_2[i] = w[i+8];

    // get g_3 = ftable( g2 XOR k1) XOR g1
    XOR(g_2, k1, temp_array, 8);
    f_table(temp_array, fvalue);
    XOR(g_1, fvalue, g_3, 8);

    // get g_4 = ftable( g3 XOR k2) XOR g2
    XOR(g_3, k2, temp_array, 8);
    f_table(temp_array, fvalue);
    XOR(g_2, fvalue, g_4, 8);

    // get g_5 = ftable( g4 XOR k3) XOR g3
    XOR(g_4, k3, temp_array, 8);
    f_table(temp_array, fvalue);
    XOR(g_3, fvalue, g_5, 8);

    // get g_6 = ftable( g5 XOR k4) XOR g4
    XOR(g_5, k4, temp_array, 8);
    f_table(temp_array, fvalue);
    XOR(g_4, fvalue, g_6, 8);

    for (int i = 0; i < 8; i++)
      output[i] = g_5[i];

    for (int i = 0; i < 8; i++)
      output[i+8] = g_6[i];

    return;
  }

  void split_R(int *R_0, int *R_1, int *R_2, int *R_3, int *R_sequence) {

    // first 16 bits of input block into w_0
    int i = 0;
    for (int j = 0; j < 16; j++) {
      R_0[i] = R_sequence[j];
      i++;
    }

    // second 16 bits of input block into w_1
    i = 0;
    for (int j = 16; j < 32; j++) {
      R_1[i] = R_sequence[j];
      i++;
    }

    // third 16 bits of input block into w_2
    i = 0;
    for (int j = 32; j < 48; j++) {
      R_2[i] = R_sequence[j];
      i++;
    }

    // last 16 bits of input block into w_3
    i = 0;
    for (int j = 48; j < 64; j++) {
      R_3[i] = R_sequence[j];
      i++;
    }

    return;
  }

  void leftRotate(int * sequence, int size) {
    int temp = sequence[0];
    for (int i = 0; i < (size - 1); i++) 
      sequence[i] = sequence[i+1];
    sequence[size - 1] = temp;
    return;
  }

  void rightRotate(int * sequence, int size) {
    int temp = sequence[size - 1];
    for (int i = size-1; i > 0; i--) 
      sequence[i] = sequence[i-1];
    sequence[0] = temp;
    return;
  }

  void printBlock(int *block, int size){
    for (int i = 0; i < size; i++) {
      if ((i % 8 == 0) && (i != 0))
        printf(" ");
      printf("%d", block[i]);
      
    }
    printf("\n");
    return;
  }

  void XOR(int *input_1, int *input_2, int *output, int size) {
    for (int i = 0; i < size; i++) {
      if (input_1[i] != input_2[i])
        output[i] = 1;
      else
        output[i] = 0;
    }
    return;
  }

  void f_table(int *bits, int *output) {
    int row = 0, col = 0;
    unsigned char fvalue_hex;

    // get the row value
    if (bits[0] == 1)
      row += 8;
    if (bits[1] == 1)
      row += 4;
    if (bits[2] == 1)
      row += 2;
    if (bits[3] == 1)
      row += 1;

    // get the column value
    if (bits[4] == 1)
      col += 8;
    if (bits[5] == 1)
      col += 4;
    if (bits[6] == 1)
      col += 2;
    if (bits[7] == 1)
      col += 1;

    fvalue_hex = ftable[row][col];

    for(int i = 0; i < 8; i++)
      output[7-i] = (fvalue_hex >> i) & 1;

    return;
  }

  int add_binary(int *b1, int *b2, int *b3) {

    // decimal representations for b1, b2, and b3
    int d1 = 0, d2 = 0, d3 = 0;
    int n = 1;

    // get decimal value of b1
    for (int i = 15; i >= 0; i--) {
      d1 += b1[i] * n;
      n *= 2;
    }

    n = 1;

    // get decimal value of b2
    for (int i = 16; i >= 0; i--) {
      d2 += b2[i] * n;
      n *= 2;
    }

    n = 1;

    // get decimal value of b3
    for (int i = 15; i >= 0; i--) {
      d3 += b3[i] * n;
      n *= 2;
    }

    return d1 + d2 + d3;

  }