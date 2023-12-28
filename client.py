import threading
import socket
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from base64 import b64encode
import hashlib
import time
import requests
from configparser import ConfigParser
import csv
import json


def encrypt_message(key, message):
    iv = b'\x00' * 16  # Initialization vector, you can generate a random IV for each message
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(message.encode('utf-8')) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return b64encode(iv + ciphertext).decode('utf-8')


def hash_password(password):
    # Use a secure hashing algorithm to hash the password
    # For example:
    hashed_password = hashlib.sha256(password.encode('utf-8')).digest()
    return hashed_password


def register_user(username, hashed_password):
    with open('registeredUsers.csv', 'a+', newline='') as csvfile:
        reader = csv.reader(csvfile)
        for row in reader:
            if row and row[0] == username:
                print("User already registered.")
                return

        writer = csv.writer(csvfile)
        writer.writerow([username, hashed_password])
        print("User registered successfully.")


def check_credentials(username, hashed_password):
    with open('registeredUsers.csv', 'r') as csvfile:
        reader = csv.reader(csvfile)
        for row in reader:
            if row and row[0] == username:
                if row[1] == hashed_password:
                    return True
                else:
                    print("Incorrect password.")
                    return False

        print("User not found.")
        return False


# def scan_url(url):
#     # Construct the URL for scanning

#     apiurl = "https://www.virustotal.com/api/v3/urls"
#     payload = {"url": f'{url}'}
#     headers = {
#         "accept": "application/json",
#         "x-apikey": 'ddba54d29f6a46137aff14d2f1dd3e0ef2589e9fb811a1daca7562cda3dae120',
#         "content-type": "application/x-www-form-urlencoded"
#     }
#     # Make the request to VirusTotal
#     response = requests.post(apiurl, data=payload, headers=headers)

#     # Check the response
#     if response.status_code == 200:
#         result = response.json()
#         print(f"Scan result for URL '{url}': {result}")
#     else:
#         print(f"Error scanning URL '{url}': {response.text}")


host = socket.gethostname()
port = 9999
key = b'Sixteen byte key'

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host, port))

# User Registration or Login
username = input("Enter your username: ")
password = input("Enter your password: ")

# Hash the password before sending it to the server
hashed_password = hash_password(password)

# Check if the user exists and the password is correct
if not check_credentials(username, hashed_password):
    print("Authentication failed. Exiting...")
    s.close()
    exit()

# Send the username and hashed password to the server for registration or login
s.send(username.encode('utf-8'))
s.send(hashed_password)


def send_messages():
    while not exit_flag.is_set():
        message = input("Enter your message or URL (type 'stop chat' to exit): ")


        encrypted_msg = encrypt_message(key, message)
        s.send(encrypted_msg.encode('utf-8'))

        if message.lower() == "stop chat":
            print("Chat has stopped")
            exit_flag.set()  # Set the flag to signal the thread to stop


# Start a new thread for sending messages
exit_flag = threading.Event()
send_thread = threading.Thread(target=send_messages)
send_thread.start()

# Check the connection status periodically
while not exit_flag.is_set():
    time.sleep(1)  # Adjust the sleep duration as needed
    try:
        # Attempt to receive a small amount of data from the server
        s.recv(1)
    except socket.error as e:
        # Handle the exception, e.g., print a message and set the exit flag
        print(f"Error checking connection status: {e}")
        exit_flag.set()

# Wait for the sending thread to finish
send_thread.join()

# Close the socket
s.close()