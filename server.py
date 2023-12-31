import socket
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from base64 import b64decode
import hashlib
import csv
import datetime
import threading

file_lock = threading.Lock() #for thread safety

def decrypt_message(key, ciphertext):
    ciphertext = b64decode(ciphertext)
    iv = ciphertext[:16]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(128).unpadder()
    decrypted_data = decryptor.update(ciphertext[16:]) + decryptor.finalize()
    plaintext = unpadder.update(decrypted_data) + unpadder.finalize()
    return plaintext.decode('utf-8')

def start_new_client_thread(clientsocket, addr, key):
    thread = threading.Thread(target=handle_client, args=(clientsocket, addr, key))
    thread.start()

def handle_client(clientsocket, addr, key):
    print("Got a connection from %s" % str(addr))
    # Receive client name and hashed password
    client_info = clientsocket.recv(1024).decode('utf-8')
    client_name, hashed_password = client_info.split('\n')
    print("Received client_name:", client_name)

    while True:
        encrypted_msg = clientsocket.recv(1024).decode('utf-8')
        decrypted_msg = decrypt_message(key, encrypted_msg)

        # Send the decrypted message back to the client
        clientsocket.send(decrypted_msg.encode('utf-8'))
        current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if decrypted_msg.strip():  # Check if the decrypted message is non-empty
            if decrypted_msg.lower() != 'stop chat':  # Check if the message is not 'stop chat'
                with file_lock:
            # Lock the file access before writing
                    with open("all_chat_history.csv", "a", newline='') as all_chat_file:
                        writer = csv.writer(all_chat_file)
                        writer.writerow([current_time, client_name, decrypted_msg])


        if decrypted_msg.lower() == "stop chat":
                print("Chat has been terminated")
                break
        
    
    clientsocket.close()
    print("Client %s disconnected" % client_name)

host = socket.gethostname()
port = 8888
key = b'Sixteen byte key'

serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
serversocket.bind((host, port))
serversocket.listen(5)

while True:
    clientsocket, addr = serversocket.accept()
    start_new_client_thread(clientsocket, addr, key)
