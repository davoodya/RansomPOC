from os import path

drives = [f"{x}:\\" for x in "ABCDEFGHIJKLMNOPQRSTUVWXYZ" if path.exists(f"{x}:\\")]
print(drives)