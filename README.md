Ben Mikailenko
ben.mikailenko@wsu.edu

CS 427
Project 1
WSU Crypt

Program encrypts or decrypts text files using the TwoFish algorithm

Files:
	bitStream.c - c code for handling input/output of bits
	wsu-crypt.c - c code for interface 
	decode.c    - c code for decrypting
	encode.c    - c code for encrypting
	bitStream.h - header file for bitStream functions
	wsucrypt    - header file for encryption functions
	Makefile    - makefile for c and header files
	wsu-crypt   - executable file for program

To compile:
	make

To clean:
	make clean

To run:

	./wsu-crypt -(e to encrypt / d to decrypt) -k <keyfile> -in <inputfile> -out <outputfile>

	ex:
	./wsu-crypt -e -k key.txt -in plaintext.txt -out ciphertext.txt (encryption)_
	./wsu-crypt -d -k key.txt -in ciphertext.txt -out decrypted.txt (decryption)
	
	note: any text file may be used for key, input, or output.


