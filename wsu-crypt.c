#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <wsucrypt.h>

extern int errno;

typedef struct _ioContext {
	FILE* input;
	FILE* output;
	FILE* key;
} IOcontext;

// function reads in one byte from context->input
int readFunc(void* context) {
	return fgetc(((IOcontext*) context)->input);
}

// function reads in one byte from context->key
int readKeyFunc(void* context) {
	return fgetc(((IOcontext*) context)->key);
}

// function writes one byte to context->output
void writeFunc(unsigned char c, void* context) {
	putc(c,((IOcontext*) context)->output);
}

int main(int argc, char * argv[]){
	int status, errnum;
	bool encoding = false;
	bool decoding = false;
	char key[128], in[128], out[128];
	IOcontext* io = malloc(sizeof(IOcontext));

	// ERROR: Not enough arguments
	if (argc < 5) {
		printf("ERROR: Not enough arguments\ncorrect arguments example:\n./wsu-crypt -e -k key.txt -in plaintext.txt -out ciphertext.txt\n");
		return 0;
	}

	// ERROR: Too many arguments
	if (argc > 8) {
		printf("ERROR: Too many arguments\ncorrect arguments example:\n./wsu-crypt -e -k key.txt -in plaintext.txt -out ciphertext.txt\n");
		return 0;
	}

	//
	//	Parse argv for input arguments
	//
    for (int i = 0; i < argc; ++i) { 

		// encoding flag
		if (strcmp(argv[i], "-e") == 0) encoding = true;

		// decoding flag
		if (strcmp(argv[i], "-d") == 0) decoding = true;

		// key file
		if (strcmp(argv[i], "-k") == 0)
			strcpy(key, argv[i+1]);

		// input file
		if (strcmp(argv[i], "-in") == 0)
			strcpy(in, argv[i+1]);

		// output file
		if (strcmp(argv[i], "-out") == 0)
			strcpy(out, argv[i+1]);

    }

	// ERROR: wrong encoding and decoding arguments
	if ((encoding && decoding) || (!encoding && !decoding)) {
		printf("ERROR: Invalid arguments \nPlease input valid arguments, either encoding '-e' or decoding '-d'\ncorrect arguments example:\n./wsu-crypt -e -k key.txt -in plaintext.txt -out ciphertext.txt\n");
		return 0;
	}

	//
	//	Encoding
	//
	if (encoding) {

		// input file
		io->input = fopen(in, "r");

		// ERROR: no input file
		if (io->input == NULL) {
			errnum = errno;
			fprintf(stderr, "Value of errno: %d\n", errno);
			perror("Error printed by perror");
			fprintf(stderr, "Error opening file: %s\n", strerror( errnum ));
			return 0;
		}

		// key file
		io->key = fopen(key, "r");

		// ERROR: no key file
		if (io->key == NULL) {
			errnum = errno;
			fprintf(stderr, "Value of errno: %d\n", errno);
			perror("Error printed by perror");
			fprintf(stderr, "Error opening file: %s\n", strerror( errnum ));
			return 0;
		}

		// output file
		io->output = fopen(out, "w+");

		// ERROR: no output file
		if (io->output == NULL) {
			errnum = errno;
			fprintf(stderr, "Value of errno: %d\n", errno);
			perror("Error printed by perror");
			fprintf(stderr, "Error opening file: %s\n", strerror( errnum ));
			return 0;
		}

		// perform encoding from "encode.c"
		void *context = io;
		status = encode(readFunc, readKeyFunc, writeFunc, context);

	}

	//
	// Decoding
	//
	if (decoding) {

		// input file
		io->input = fopen(in, "r");

		// ERROR: no input file
		if (io->input == NULL) {
			errnum = errno;
			fprintf(stderr, "Value of errno: %d\n", errno);
			perror("Error printed by perror");
			fprintf(stderr, "Error opening file: %s\n", strerror( errnum ));
			return 0;
		}

		// key file
		io->key = fopen(key, "r");

		// ERROR: no key file
		if (io->key == NULL) {
			errnum = errno;
			fprintf(stderr, "Value of errno: %d\n", errno);
			perror("Error printed by perror");
			fprintf(stderr, "Error opening file: %s\n", strerror( errnum ));
			return 0;
		}

		// output file
		io->output = fopen(out, "w+");

		// ERROR: no output file
		if (io->output == NULL) {
			errnum = errno;
			fprintf(stderr, "Value of errno: %d\n", errno);
			perror("Error printed by perror");
			fprintf(stderr, "Error opening file: %s\n", strerror( errnum ));
			return 0;
		}

		// perform decoding from "decode.c"
		void *context = io;
		status = decode(readFunc, readKeyFunc, writeFunc, context);

	}

	// ERROR: failed to encode / decode
	if (status == 1) {
		printf("Program failed to execute\n");
	} else {
		printf("Program executed sucessfully\n");
	}

	// close io and free memory
	fclose(io->input);
	fclose(io->key);
	fclose(io->output);
	free(io);

	return 0;

}
