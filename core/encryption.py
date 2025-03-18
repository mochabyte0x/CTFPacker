import os

from core.utils import Colors
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

class Encryption:
    
    # Generate a random KEY and IV
    def GenerateKey(key_size: int) -> tuple:
        # Generate a 16-byte or 32-byte key for AES-128 or AES-256
        key = os.urandom(key_size)
        #print(key)
        # Generate a 16-byte IV (128 bits, which is the block size for AES)
        iv = os.urandom(AES.block_size)
        #print(iv)
        
        return key, iv

    # AES-128 CBC encryption
    def EncryptAES(shellcode: bytes) -> bytes:
        #print(Colors.light_blue("[INF] Encryption Technique:\tAES-128-CBC"))

        # Generate random key and IV
        key, iv = Encryption.GenerateKey(16)

        # Formatting 
        hex_key = ''.join([f"0x{key.hex()[i:i+2]}, " for i in range(0, len(key.hex()), 2)]).strip(", ")
        hex_iv = ''.join([f"0x{iv.hex()[i:i+2]}, " for i in range(0, len(iv.hex()), 2)]).strip(", ")

        # Print the key and IV
        #print(Colors.light_blue(f"[INF] Key (hex):\t\t{hex_key}"))
        #print(Colors.light_blue(f"[INF] IV (hex):\t\t\t{hex_iv}\n"))

        # Create AES cipher in CBC mode
        cipher = AES.new(key, AES.MODE_CBC, iv)

        # Pad the shellcode to be a multiple of 16 bytes (AES block size)
        padded_shellcode = pad(shellcode, AES.block_size)

        # Encrypt the padded shellcode
        enc_shellcode = cipher.encrypt(padded_shellcode)

        # Return the encrypted shellcode
        return enc_shellcode, hex_key, hex_iv