CC=gcc

wsu-crypt: wsu-crypt.c decode.c encode.c bitStream.c 
	$(CC) -o wsu-crypt wsu-crypt.c decode.c encode.c bitStream.c -I.

clean:
	rm -f wsu-crypt
