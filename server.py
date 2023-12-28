import socket
import _thread
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from base64 import b64decode
import hashlib
import csv
import datetime

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
    # Receive client_name and hashed_password
    client_info = clientsocket.recv(1024).decode('utf-8')
    client_name, hashed_password = client_info.split('\n')


    print("Received client_name:", client_name)
    print("Received hashed_password:", hashed_password)

    while True:
        encrypted_msg = clientsocket.recv(1024).decode('utf-8')
        decrypted_msg = decrypt_message(key, encrypted_msg)

        #print("Received message from %s: %s" % (client_name, decrypted_msg))
        #print("Encrypted message:", encrypted_msg)
        # Send the decrypted message back to the client
        clientsocket.send(decrypted_msg.encode('utf-8'))

        current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Log the message to a CSV file with username, timestamp, and message
        with open("all_chat_history.csv", "a", newline='') as all_chat_file:
            writer = csv.writer(all_chat_file)
            writer.writerow([current_time, client_name, decrypted_msg])

        if decrypted_msg.lower() == "stop chat":
                print("Chat has been terminated")
                break
        
        print("Client %s disconnected" % client_name)


    clientsocket.close()

host = socket.gethostname()
port = 8888
key = b'Sixteen byte key'

serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
serversocket.bind((host, port))
serversocket.listen(5)

while True:
    clientsocket, addr = serversocket.accept()
    start_new_client_thread(clientsocket, addr, key)
