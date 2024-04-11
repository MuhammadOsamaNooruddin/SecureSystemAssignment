/*
 *		 Name: Muhammad Osama Noor Uddin, Student Number: D23124872
		
 */

#include <stdlib.h>
#include <stdio.h>
// TODO: Any other files you need to include should go here

#include "rijndael.h"
#include <string.h>

/* Common functions that will be used in both encryption and decryption */

/* table for S_box */
unsigned char s_box[256] =
{
	0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
	0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
	0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
	0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
	0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
	0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
	0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
	0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
	0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
	0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
	0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
	0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
	0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
	0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
	0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
	0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};

/* table for Inverse S_box */
unsigned char inv_s[256] =
{
	0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
	0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
	0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
	0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
	0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
	0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
	0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
	0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
	0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
	0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
	0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
	0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
	0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
	0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
	0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
	0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
};


unsigned char gmul(unsigned char rhs, unsigned char lhs) {
	unsigned char peasant = 0;
	unsigned int irreducible = 0x11b;
	while (lhs) {
		if (lhs & 1) {
			peasant = peasant ^ rhs;
		}
		if (rhs & 0x80) {
			rhs = (rhs << 1) ^ irreducible;
		}
		else {
			rhs = rhs << 1;
		}
		lhs = lhs >> 1;
	}
	return peasant;
}

/** table for rcon*/
unsigned char rcon[16] = {
	0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
};
/* Common functions that will be used in both encryption and decryption */

/*
 * Operations used when encrypting a block
 */

/* Substitutes each byte with a value from a pre-computed S-box */
void sub_bytes(unsigned char * plain_text) {
	for (int i = 0; i < AES_SIZE; i++) {
		plain_text[i] = s_box[plain_text[i]];
	}
}

/* This function will shift the rows to the left except row 0
 * which will not be shifted
 e.g: Row 0 : no shifting in this row
	  Row 1 : 1 shift to the left
	  Row 2 : 2 shifts to the left
	  Row 3 : 3 shifts to the left
 
*/
void shift_rows(unsigned char * plain_text) {
	unsigned char temp_block[AES_SIZE];

	for (int i = 0; i < AES_SIZE; i += 4) {
		//incrementing by 5 causes the diagonal shift effect
		temp_block[i] = plain_text[i];
		temp_block[i + 1] = plain_text[(i + 5) % AES_SIZE];
		temp_block[i + 2] = plain_text[(i + 10) % AES_SIZE];
		temp_block[i + 3] = plain_text[(i + 15) % AES_SIZE];
	}

	for (int i = 0; i < AES_SIZE; i++) {
		plain_text[i] = temp_block[i];
	}
}

/* This function will mix the columns of the block
 * by using gmul function to multiply the columns
 */
void mix_columns(unsigned char *plain_text) {

	unsigned char temp_block[AES_SIZE];

	for (int i = 0; i < AES_SIZE; i += 4) {

		temp_block[i] = gmul(plain_text[i], (unsigned char)2) ^ gmul(plain_text[i + 1], (unsigned char)3) ^ plain_text[i + 2] ^ plain_text[i + 3];
		temp_block[i + 1] = plain_text[i] ^ gmul(plain_text[i + 1], (unsigned char) 2) ^ gmul(plain_text[i + 2], (unsigned char) 3) ^ plain_text[i + 3];
		temp_block[i + 2] = plain_text[i] ^ plain_text[i + 1] ^ gmul(plain_text[i + 2], (unsigned char) 2) ^ gmul(plain_text[i + 3], (unsigned char) 3);
		temp_block[i + 3] = gmul(plain_text[i], (unsigned char) 3) ^ plain_text[i + 1] ^ plain_text[i + 2] ^ gmul(plain_text[i + 3], (unsigned char) 2);
	}

	for (int i = 0; i < AES_SIZE; i++) {
		plain_text[i] = temp_block[i];
	}
}

/*
 * Operations used when decrypting a block
 */

/* Substitutes each byte with a value from a pre-computed inverse S-box */
void invert_sub_bytes(unsigned char * state) {
	for (int i = 0; i < AES_SIZE; i++) {
		state[i] = inv_s[state[i]];
	}
}

/* This function will inverts the shift rows operation */
void invert_shift_rows(unsigned char * plain_text) {
	unsigned char temp_block[AES_SIZE];

	for (int i = 0; i < AES_SIZE; i += 4) {
		//incrementing by 5 causes the diagonal shift effect
		temp_block[i] = plain_text[i];
		temp_block[(i + 5) % AES_SIZE] = plain_text[i+1];
		temp_block[(i + 10) % AES_SIZE] = plain_text[i+2];
		temp_block[(i + 15) % AES_SIZE] = plain_text[i+3];
	}

	for (int i = 0; i < AES_SIZE; i++) {
		plain_text[i] = temp_block[i];
	}
}

/* This function will invert the mix columns operation using gmul function */
void invert_mix_columns(unsigned char *plain_text) {

	unsigned char temp_block[AES_SIZE];

	for (int i = 0; i < AES_SIZE; i += 4) { 
	//inverse multiplication > 9,11,13,14
		temp_block[i] = gmul(plain_text[i], (unsigned char) 14) ^ gmul(plain_text[i + 1], (unsigned char)11) ^ 
			gmul(plain_text[i + 2], (unsigned char)13) ^ gmul(plain_text[i + 3], (unsigned char)9);

		temp_block[i + 1] = gmul(plain_text[i], (unsigned char) 9) ^ gmul(plain_text[i + 1], (unsigned char)14) ^ 
			gmul(plain_text[i + 2], (unsigned char)11) ^ gmul(plain_text[i + 3], (unsigned char)13);

		temp_block[i + 2] = gmul(plain_text[i], (unsigned char)13) ^ gmul(plain_text[i + 1], (unsigned char)9) ^ 
			gmul(plain_text[i + 2], (unsigned char)14) ^ gmul(plain_text[i + 3], (unsigned char)11);

		temp_block[i + 3] = gmul(plain_text[i], (unsigned char)11) ^ gmul(plain_text[i + 1], (unsigned char)13) ^ 
			gmul(plain_text[i + 2], (unsigned char)9) ^ gmul(plain_text[i + 3], (unsigned char)14);
	}

    for (int i = 0; i < AES_SIZE; i++) {
		plain_text[i] = temp_block[i];
	}
}

/*
 * This operation is shared between encryption and decryption
 */
/* This function will Adds the round key to the block, by xoring each corresponding byte */
void add_round_key(unsigned char * plain_text, unsigned char * roundKey)
{
	for (int i = 0; i < AES_SIZE; i++) {
		plain_text[i] = plain_text[i] ^ roundKey[i];
	}
}

/*
 * This function should expand the round key. Given an input,
 * which is a single 128-bit key, it should return a 176-byte
 * vector, containing the 11 round keys one after the other
 */
unsigned char *expand_key(unsigned char *key_for_Cipher) {

	// Allocate memory for the expanded key
	unsigned char *expanded_Key = malloc(176); 
	if (!expanded_Key) return NULL; //if memory allocation fails

	// variables for the key expansion process
	int bytesGenerated = 0;
	int rcon_location = 1; 
	unsigned char key_block[4];

	// Copy initial key to expanded key
	for (int i = 0; i < AES_SIZE; i++) {
		expanded_Key[i] = key_for_Cipher[i];
	}
	bytesGenerated += AES_SIZE;

	// key expansion loop until all round keys are generated
	while (bytesGenerated < (AES_SIZE * (NUM_ROUNDS + 1))) {
        // Extract a 32-bit word from the expanded key
        for (int i = 0; i < ((AES_SIZE * 8) / 32); i++) {
            key_block[i] = expanded_Key[i + bytesGenerated - ((AES_SIZE * 8) / 32)];
        }

        // this is handle the first word of each block
        if (bytesGenerated % AES_SIZE == 0) {
            // perform a circular left shift on the word to rotate the bytes
            unsigned char c = key_block[0];
            for (int i = 0; i < 3; i++) {
                key_block[i] = key_block[i + 1];
            }
            key_block[3] = c;

            // here applying S-Box substitution on each byte of the word
            for (int i = 0; i < 4; ++i) {
                key_block[i] = s_box[key_block[i]];
            }

            // xor with rcon, where only the first byte is used
            key_block[0] = key_block[0] ^ rcon[rcon_location++];
        }

        // the other words of the round key will behave the same
        for (int i = 0; i < 4; i++) {
            expanded_Key[bytesGenerated] = expanded_Key[bytesGenerated - AES_SIZE] ^ key_block[i];
            bytesGenerated++;
        }
    }
	return expanded_Key;
}

/*
 * The implementations of the functions declared in the
 * header file is implemented here
 */

unsigned char *aes_encrypt_block(unsigned char *plaintext, unsigned char *key) {
	// Allocate memory for the cipher output
	unsigned char *cipher_output =(unsigned char *)malloc(sizeof(unsigned char) * AES_SIZE);
	if (!cipher_output) return NULL; //if memory allocation fails

	// expand the key for the round keys generation
	unsigned char *expandedKey = expand_key(key);
	// copy the plaintext to the cipher output buffer
	for (int i = 0; i < AES_SIZE; i++) {
		cipher_output[i] = plaintext[i];
	}

	// Round 1, initial round for the add round key operation
	add_round_key(cipher_output, expandedKey);

	// round 2-9, main rounds of the encryption process
	for (int i = 1; i < NUM_ROUNDS; i++) {
		sub_bytes(cipher_output); //substitute bytes using s-box
		shift_rows(cipher_output); // apply shift rows operation on the block 
		mix_columns(cipher_output); // apply mix columns operation on the block
		add_round_key(cipher_output, expandedKey + (AES_SIZE * i)); // apply add round key operation on the block
	}
	// final round 10, no mix columns operation applied here rest of the operations are the same sub_bytes, shift_rows, add_round_key
	sub_bytes(cipher_output);
	shift_rows(cipher_output);
	add_round_key(cipher_output, expandedKey + (AES_SIZE * NUM_ROUNDS));  
	// free the memory allocated for the expanded key
	free(expandedKey);

	return cipher_output;
}


unsigned char* aes_decrypt_block(unsigned char *cipher_text, unsigned char *key) {
	// Allocate memory for the output
	unsigned char *output = (unsigned char *)malloc(sizeof(unsigned char) * AES_SIZE);
	if (!output) return NULL; //if memory allocation fails

	// expand the key for the round keys generation
    unsigned char *expanded_Key = expand_key(key);
	// copy the cipher text to the output buffer
	for (int i = 0; i < AES_SIZE; i++) {
		output[i] = cipher_text[i];
	}

	// Round 1, initial round for the add round key operation
    add_round_key(output, expanded_Key + (AES_SIZE * NUM_ROUNDS)); // apply add round key operation on the block
    invert_shift_rows(output); // apply inverse shift rows operation on the block
    invert_sub_bytes(output); // apply inverse sub bytes operation on the block

	// round 2-9, main rounds of the decryption process
    for (int i = NUM_ROUNDS - 1; i >= 1; i--) {
        add_round_key(output, expanded_Key + (AES_SIZE * i)); // apply add round key operation on the block
        invert_mix_columns(output); // apply inverse mix columns operation on the block
        invert_shift_rows(output); // apply inverse shift rows operation on the block
        invert_sub_bytes(output); // apply inverse sub bytes operation on the block

    }

	// add round key operation for the final round
    add_round_key(output, expanded_Key);
	free(expanded_Key); // free the memory allocated for the expanded key
	return output;

}
