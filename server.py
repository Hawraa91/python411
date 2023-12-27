import socket
import _thread
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from base64 import b64decode
import hashlib
import csv

def decrypt_message(key, ciphertext):
    ciphertext = b64decode(ciphertext)
    iv = ciphertext[:16]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(128).unpadder()
    decrypted_data = decryptor.update(ciphertext[16:]) + decryptor.finalize()
    plaintext = unpadder.update(decrypted_data) + unpadder.finalize()
    return plaintext.decode('utf-8')

def register_user(username, hashed_password):
    with open('user_credentials.csv', 'a', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow([username, hashed_password])

def verify_credentials(username, hashed_password):
    with open('user_credentials.csv', 'r') as csvfile:
        reader = csv.reader(csvfile)
        for row in reader:
            if row[0] == username and row[1] == hashed_password:
                return True
    return False

def start_new_client_thread(clientsocket, addr, key):
    _thread.start_new_thread(handle_client, (clientsocket, addr, key))

def handle_client(clientsocket, addr, key):
    print("Got a connection from %s" % str(addr))
    print("hi")
    # Receive client_name and hashed_password
    client_info = clientsocket.recv(1024).decode('utf-8')
    client_name, hashed_password = client_info.split('\n')


    print("Received client_name:", client_name)
    print("Received hashed_password:", hashed_password)


    # if verify_credentials(client_name, hashed_password):
    #     print("Client name:", client_name)
    #     register_user(client_name, hashed_password)
    #     print("Registered Users:")
    #     with open('user_credentials.csv', 'r') as csvfile:
    #         reader = csv.reader(csvfile)
    #         for row in reader:
    #             print(f"- {row[0]}")

    while True:
        encrypted_msg = clientsocket.recv(1024).decode('utf-8')
        decrypted_msg = decrypt_message(key, encrypted_msg)

        print("Received message from %s: %s" % (client_name, decrypted_msg))
        print("Encrypted message:", encrypted_msg)

        if decrypted_msg.lower() == "stop chat":
                print("Chat has been terminated")
                break

    print("Client %s disconnected" % client_name)
    #else:
        #print("Invalid username or password. Disconnecting client.")

    clientsocket.close()

host = socket.gethostname()
port = 9999
key = b'Sixteen byte key'

serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
serversocket.bind((host, port))
serversocket.listen(5)

while True:
    clientsocket, addr = serversocket.accept()
    start_new_client_thread(clientsocket, addr, key)