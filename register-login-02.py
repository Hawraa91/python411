import tkinter as tk
from tkinter import messagebox
import hashlib
import csv
import socket
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from base64 import b64encode, b64decode
import requests

class AuthenticationApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Login and Register")

        # Variables to store input values
        self.username_var = tk.StringVar()
        self.password_var = tk.StringVar()
        self.new_username_var = tk.StringVar()
        self.new_password_var = tk.StringVar()

        # Load user credentials from the CSV file
        self.user_credentials = self.load_user_credentials()

        self.send_button = tk.Button(root, text="Send Message", command=self.send_message)
        self.send_button.grid(row=3, column=0, columnspan=2, pady=10)

        # Socket variables
        self.clientsocket = None
        self.key = b'Sixteen byte key'
        self.hashed_password = ''
        self.conversation_text = None
        self.new_message_entry = None

        # Create widgets for login page
        self.label_username = tk.Label(root, text="Username:")
        self.entry_username = tk.Entry(root, textvariable=self.username_var)
        self.label_password = tk.Label(root, text="Password:")
        self.entry_password = tk.Entry(root, textvariable=self.password_var, show="*")
        self.login_button = tk.Button(root, text="Login", command=self.login)
        self.switch_to_register_button = tk.Button(root, text="Don't have an account? Register", command=self.switch_to_register)

        # Place widgets on the grid
        self.label_username.grid(row=0, column=0, pady=5)
        self.entry_username.grid(row=0, column=1, pady=5)
        self.label_password.grid(row=1, column=0, pady=5)
        self.entry_password.grid(row=1, column=1, pady=5)
        self.login_button.grid(row=2, column=0, columnspan=2, pady=10)
        self.switch_to_register_button.grid(row=3, column=0, columnspan=2, pady=5)

        # Hide register widgets initially
        self.label_new_username = tk.Label(root, text="New Username:")
        self.entry_new_username = tk.Entry(root, textvariable=self.new_username_var)
        self.label_new_password = tk.Label(root, text="New Password:")
        self.entry_new_password = tk.Entry(root, textvariable=self.new_password_var, show="*")
        self.register_button = tk.Button(root, text="Register", command=self.register)
        self.switch_to_login_button = tk.Button(root, text="Already have an account? Login", command=self.switch_to_login)
        self.add_user_button = tk.Button(root, text="Add User", command=self.switch_to_register)

        self.label_new_username.grid_forget()
        self.entry_new_username.grid_forget()
        self.label_new_password.grid_forget()
        self.entry_new_password.grid_forget()
        self.register_button.grid_forget()
        self.switch_to_login_button.grid_forget()
        self.add_user_button.grid_forget()

    def encrypt_message(self, plaintext):
        plaintext = plaintext.encode('utf-8')
        iv = b'1234567890123456'  # You should use a random IV for each message in a real-world scenario
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext) + padder.finalize()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return b64encode(iv + ciphertext).decode('utf-8')

    def login(self):
        username = self.username_var.get()
        password = self.password_var.get()
        hashed = hashlib.sha256(password.encode('utf-8')).hexdigest()

        for user in self.user_credentials:
            if user["username"] == username and user["password"] == hashlib.sha256(password.encode('utf-8')).hexdigest():
                messagebox.showinfo("Login Successful", "Welcome, {}!".format(username))
                self.open_chat_page(username, hashed)
                return

        messagebox.showerror("Login Failed", "Invalid username or password")

    def load_user_credentials(self):
        # Load user credentials from the CSV file
        try:
            with open('user_credentials.csv', 'r', newline='') as csvfile:
                reader = csv.DictReader(csvfile)
                return list(reader)
        except FileNotFoundError:
            return []

    def save_user_credentials(self):
        # Save user credentials to the CSV file
        with open('user_credentials.csv', 'w', newline='') as csvfile:
            fieldnames = ['username', 'password']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

            # Write header if the file is empty
            if csvfile.tell() == 0:
                writer.writeheader()

            # Write each user's credentials
            for user in self.user_credentials:
                writer.writerow(user)

    def register(self):
        new_username = self.new_username_var.get()
        new_password = self.new_password_var.get()

        for user in self.user_credentials:
            if user["username"] == new_username:
                messagebox.showerror("Registration Failed", "Username already exists")
                return

        # Hash the new password
        hashed_password = hashlib.sha256(new_password.encode('utf-8')).hexdigest()

        # Add new user credentials to the list
        new_user = {"username": new_username, "password": hashed_password}
        self.user_credentials.append(new_user)

        # Save updated user credentials to the CSV file
        self.save_user_credentials()

        messagebox.showinfo("Registration Successful", "User {} registered successfully!".format(new_username))
        self.switch_to_login()

    def switch_to_register(self):
        self.label_username.grid_forget()
        self.entry_username.grid_forget()
        self.label_password.grid_forget()
        self.entry_password.grid_forget()
        self.login_button.grid_forget()
        self.switch_to_register_button.grid_forget()

        self.label_new_username.grid(row=0, column=0, pady=5)
        self.entry_new_username.grid(row=0, column=1, pady=5)
        self.label_new_password.grid(row=1, column=0, pady=5)
        self.entry_new_password.grid(row=1, column=1, pady=5)
        self.register_button.grid(row=2, column=0, columnspan=2, pady=10)
        self.switch_to_login_button.grid(row=3, column=0, columnspan=2, pady=5)
        self.add_user_button.grid(row=4, column=0, columnspan=2, pady=5)

    def switch_to_login(self):
        self.label_new_username.grid_forget()
        self.entry_new_username.grid_forget()
        self.label_new_password.grid_forget()
        self.entry_new_password.grid_forget()
        self.register_button.grid_forget()
        self.switch_to_login_button.grid_forget()
        self.add_user_button.grid_forget()

        self.label_username.grid(row=0, column=0, pady=5)
        self.entry_username.grid(row=0, column=1, pady=5)
        self.label_password.grid(row=1, column=0, pady=5)
        self.entry_password.grid(row=1, column=1, pady=5)
        self.login_button.grid(row=2, column=0, columnspan=2, pady=10)
        self.switch_to_register_button.grid(row=3, column=0, columnspan=2, pady=5)
        self.add_user_button.grid(row=4, column=0, columnspan=2, pady=5)

    def open_chat_page(self, username, hashed_password):
        # Create a new window for the chat page
        chat_window = tk.Toplevel(self.root)
        chat_window.title("Chat Page - {}".format(username))
        # Create a socket for the client
        self.clientsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.clientsocket.connect((socket.gethostname(), 8888))

        # Send username and hashed password to the server
        self.clientsocket.send((username + '\n' + self.hashed_password).encode('utf-8'))

        self.send_button.config(state=tk.NORMAL)  # Enable the send button

        # Initialize conversation_text widget
        conversation_label = tk.Label(chat_window, text="Conversation:")
        self.conversation_text = tk.Text(chat_window, height=30, width=100)
        new_message_label = tk.Label(chat_window, text="New Message:")
        self.new_message_entry = tk.Entry(chat_window, width=50)
        send_button = tk.Button(chat_window, text="Send", command=self.send_message)

        # Contacts placeholder
        contacts_label = tk.Label(chat_window, text="Contacts:")
        contacts_text = tk.Text(chat_window, height=5, width=30)

        # Place widgets on the chat page grid
        conversation_label.grid(row=0, column=0, columnspan=2, pady=5)
        self.conversation_text.grid(row=1, column=0, columnspan=2, pady=5)
        new_message_label.grid(row=2, column=0, pady=5)
        self.new_message_entry.grid(row=2, column=1, pady=5)
        send_button.grid(row=3, column=0, columnspan=2, pady=10)
        contacts_label.grid(row=0, column=2, pady=5)
        contacts_text.grid(row=1, column=2, rowspan=3, pady=5)
     
    @staticmethod   
    def scanUrl(url):
    # Construct the URL for scanning
        apiurl = "https://www.virustotal.com/api/v3/urls"
        payload = {"url": f'{url}'}
        headers = {
            "accept": "application/json",
            "x-apikey": 'ddba54d29f6a46137aff14d2f1dd3e0ef2589e9fb811a1daca7562cda3dae120',
            "content-type": "application/x-www-form-urlencoded"
        }
        # Make the request to VirusTotal
        response = requests.post(apiurl, data=payload, headers=headers)

        # Check the response
        if response.status_code == 200:
            result = response.json()
            print(f"Scan result for URL '{url}': {result}")
            return result
        else:
            print(f"Error scanning URL '{url}': {response.text}")
            return 'error scanning URL'


        
    def send_message(self):
        if not self.clientsocket:
            messagebox.showerror("Error", "Not connected to the server.")
            return

        message = self.new_message_entry.get()
        self.new_message_entry.delete(0, tk.END)

        # Encrypt and send the message
        encrypted_msg = self.encrypt_message(message)
        
        self.clientsocket.send(encrypted_msg.encode('utf-8'))
        
        self.conversation_text.insert(tk.END, f"server encrypted: {encrypted_msg}\n")
        #decrypted_msg= self.decrypt_message(message)
        #self.conversation_text.insert(tk.END, f"server: {decrypted_msg}\n")
        self.conversation_text.see(tk.END)  # Scroll to the bottom

        if 'http://' in message.lower() or 'https://' in message.lower():
            self.conversation_text.insert(tk.END, f'{AuthenticationApp.scanUrl(message)}')
            
        self.conversation_text.insert(tk.END, f"server decrypted: {self.clientsocket.recv(1024).decode('utf-8')}\n")

        if message.lower() == 'stop chat':
            self.clientsocket.close()
            messagebox.showinfo("Chat Closed", "Chat has been terminated.")
            self.clientsocket = None

    def display_user_chat_history(self, username):
        all_chat_history_file = "all_chat_history.csv"
        try:
            with open(all_chat_history_file, 'r') as history_file:
                reader = csv.reader(history_file)
                chat_history = "\n".join([f"{row[0]} - {row[1]}: {row[2]}" for row in reader if row[1] == username])
                # Update the Text widget to display chat history
                self.conversation_text.insert(tk.END, chat_history)
                self.conversation_text.see(tk.END)  # Scroll to the bottom
        except FileNotFoundError:
            messagebox.showinfo("Chat History", "No chat history found.")

if __name__ == "__main__":
    root = tk.Tk()
    app = AuthenticationApp(root)
    root.mainloop()
