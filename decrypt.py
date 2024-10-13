"""Ransom Tools
Simple Decryption
Author: Yakuza-D
Disclaimer: this app written only and only for educational purpose
"""
# Step 1: Import Requires Modules for Encryption
from os import remove, path
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

"""Step 2: Deriving the Encryption key from a Simple Password"""
# Simple Password text
password = "hello"

# Create a Simple key from the password, then padded(truncated) to 32 bytes
key = password.encode().ljust(32, b'\0')[:32]

# Step 3: Create Function to Decrypt a File
def decrypt_file(file_path, input_key):
    try:
        # Read the Salt, IV & Encrypted Data from the file to be decrypted
        with open(file_path, "rb") as file:  # noqa
            salt = file.read(16)
            iv = file.read(16)
            encryptedData = file.read()

        # Create a Cipher object using the AES algorithm and the key
        cipher = AES.new(key,AES.MODE_CBC, iv)

        # Decrypt the data and Remove the padding
        decryptedData = unpad(cipher.decrypt(encryptedData), AES.block_size)

        # Remove .encrypted an extension from the file name
        originalFileName = file_path.replace(".encrypted", "")

        # Write the Decrypted Data into a new File
        with open(originalFileName, "wb") as file:  # noqa
            file.write(decryptedData)
        # Remove the encrypted file
        remove(file_path)
        print(f"[+] Decryption: Decryption successfully done => {originalFileName}")
    except Exception as e:
        print(f"[-] Decryption: Decryption Failed! => {file_path}\n[-] Error: {e}")


# Step 4: Create Main Script
if __name__ == "__main__":
    # Hardcoded filepath
    filePath = r"H:/Repo/RansomPOC/test.docx.encrypted"

    # Debug Print => for filepath to ensure is correct
    print(f"[*] Debug Info: Submitted filepath for Decrypted is => {filePath}")

    if path.exists(filePath):
        print(f"[*] Debug Info: Decryption Started for => {filePath}")
        decrypt_file(filePath, key)
    else:
        # Debug Print
        print(f"[*] Debug Info: File not found => {filePath}")
        print(f"[*] Debug Info: The absolute filepath is => {path.abspath(filePath)}")

        # Debug Print
        directory, file = path.split(filePath)
        print(f"[*] Debug Info: Directory Exists Checking => {path.isdir(directory)}")
        print(f"[*] Debug Info: File Exists Checking => {path.isfile(file)}")







