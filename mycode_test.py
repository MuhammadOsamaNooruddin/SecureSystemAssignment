import ctypes
import unittest
import os 
from aes.aes import AES 
rijndael_c = ctypes.CDLL('./rijndael.so')

# wrapper functions for calling C functions with correct argument types and return types
def aes_encrypt_block(plaintext, key):
    rijndael_c.aes_encrypt_block.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
    rijndael_c.aes_encrypt_block.restype = ctypes.POINTER(ctypes.c_char * 16)
    return rijndael_c.aes_encrypt_block(plaintext, key)

def aes_decrypt_block(encrypted_bytes, key):
    rijndael_c.aes_decrypt_block.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
    rijndael_c.aes_decrypt_block.restype = ctypes.POINTER(ctypes.c_char * 16)
    return rijndael_c.aes_decrypt_block(encrypted_bytes, key)
# wrapper functions for calling C functions with correct argument types and return types

class TestAES(unittest.TestCase):

    def test_encrypt_decrypt(self):
        
        # this for loop is tp iterate 3 times to generate 3 pairs of key and plaintext, and test encryption and decryption
        for _ in range(3):  

            # os.urandom will generate the random key and plaintext of 16 bytes
            key = os.urandom(16)
            plaintext = os.urandom(16)

            # encryption and decryption using C code
            c_encryption = aes_encrypt_block(ctypes.c_char_p(plaintext), ctypes.c_char_p(key))
            encrypted_block_c = bytes(c_encryption.contents)
            c_decryption = aes_decrypt_block(ctypes.c_char_p(encrypted_block_c), ctypes.c_char_p(key))
            decrypted_block_c = bytes(c_decryption.contents)

            # encryption and decryption using Python code
            aes_python = AES(key)
            encrypted_block_py = aes_python.encrypt_block(plaintext)
            decrypted_block_py = aes_python.decrypt_block(encrypted_block_py)
            
            self.assertEqual(encrypted_block_c, encrypted_block_py) # this will check if encrypted blocks are equal
            self.assertEqual(decrypted_block_c, plaintext) # this will check if decrypted block matches plaintext
            self.assertEqual(decrypted_block_py, plaintext) # this will check if decrypted block matches plaintext
       
if __name__ == '__main__':
    unittest.main()