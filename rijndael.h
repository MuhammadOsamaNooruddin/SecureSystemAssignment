/*
 * TODO: Add your name and student number here, along with
 *       a brief description of this code.
 */

#ifndef RIJNDAEL_H
#define RIJNDAEL_H
#define AES_SIZE 16
#define NUM_ROUNDS 10

#ifndef BLOCK_ACCESS
#define BLOCK_ACCESS(block, row, col) (block[(row * 4) + col])
#endif



/*
 * These should be the main encrypt/decrypt functions (i.e. the main
 * entry point to the library for programmes hoping to use it to
 * encrypt or decrypt data)
 */
unsigned char* aes_decrypt_block(unsigned char * plain_text, unsigned char * key);
unsigned char* aes_encrypt_block(unsigned char * plain_text, unsigned char * key);

#endif
