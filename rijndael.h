/*
 * TODO: Add your name and student number here, along with
 *       a brief description of this code.
 */

#define AES_SIZE 16 //16 bytes == 128 bits
#define NUM_ROUNDS 10

#ifndef BLOCK_ACCESS
#define BLOCK_ACCESS(block, row, col) ((block)[4 * (col) + (row)])
#endif

/*
 * These should be the main encrypt/decrypt functions (i.e. the main
 * entry point to the library for programmes hoping to use it to
 * encrypt or decrypt data)
 */
unsigned char* AES_decrypt(unsigned char * plain_text, unsigned char * key);
unsigned char* AES_encrypt(unsigned char * plain_text, unsigned char * key);