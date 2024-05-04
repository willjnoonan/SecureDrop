import socket
import os
from _thread import *
import ssl
import json
import pwinput
import bcrypt
from base64 import b64encode
from cryptoUtil import cryptoUtil
import select
import pickle
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography import x509
import secrets



crypto = cryptoUtil()

class User:
    # Initialize a User with name and email
    def __init__(self, name, email):
        self.name = name
        self.email = email

class HiddenUser:
    # Initialize a HiddenUser with name, email, contacts, password, salt, and client
    def __init__(self, name, email, contacts, password, salt):
        self.name = name
        self.email = email
        self.contacts = contacts
        self.password = password
        self.salt = salt
        self.client = None

class UserHandler:
    # Initialize a UserHandler with connection details, SSL socket, user, and contacts
    def __init__(self):
        self.connect_to_host = '127.0.0.1'
        self.connect_to_port = 52000
        self.cert_file = "clientKeys/certificate.pem"
        self.key_file = "clientKeys/key.pem"
        self.socket = self.createSSLSocket()
        self.user = self.getUser()
        self.contacts = self.getContacts()

    # Send a HiddenUser object to the server
    def sendToServer(self):
        data = json.loads(open("user.json", "r").read())
        hiddenUser = HiddenUser(self.user.name, self.user.email, self.contacts, data["password"], data["salt"])
        pkl = pickle.dumps(hiddenUser)
        try:
            self.socket.sendall(pkl)
        except ssl.SSLError as e:
            print(f"SSL error occurred: {e}")

    # Send a logout request to the server
    def logoutUser(self):
        user = self.user
        pkl = pickle.dumps(user)
        self.socket.send("LOGOUT".encode())
        self.socket.send(pkl)

    # Create a new user and save their details in a JSON file
    def createNewUser(self):
        name = input('Enter Full Name: ')
        email = input('Enter Email Address: ')
        password = pwinput.pwinput()
        reenter = pwinput.pwinput('Re-enter Password: ')
        if password != reenter:
            print("Passwords Do Not Match.")
        else:
            print("Passwords Match.")
            hashedPW = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            salt = os.urandom(16)
            salt = b64encode(salt).decode('utf-8')
            with open("user.json", "w") as output:
                output.write(json.dumps({"name": name, "email": email, "password": hashedPW, "salt": salt}))
            print("User Registered.")
            print("Exiting Secure Drop. Goodbye!")
            exit()

    # Get the user details from a JSON file and verify the login
    def getUser(self):
        if os.path.exists("user.json") is False or os.path.getsize("user.json") == 0:
            return None
        data = json.loads(open("user.json", "r").read())

        if data["name"] is None or data["email"] is None or data["password"] is None:
            return None
        
        def checkLogin():
            emailInput = input("Enter Email Address: ")
            passwordInput = pwinput.pwinput("Enter Password: ")
            if emailInput != data["email"] or bcrypt.checkpw(passwordInput.encode('utf-8'), str(data["password"]).encode('utf-8')) is False:
                print('Email and Password Combination Invalid.\n')
                return False
            else:
                return True
            
        loginSuccess = checkLogin()

        while loginSuccess is False:
            checkLogin()
            
        return User(data["name"], data["email"])

    # Get the contacts from a JSON file
    def getContacts(self):
        contacts = []
        if os.path.exists("contacts.json") is False or os.path.getsize("contacts.json") == 0:
            return []
        data = json.loads(open("contacts.json", "r").read())
        for contact in data:
            tempUser = User(contact["name"], contact["email"])
            contacts.append(tempUser)
        #print(contacts) # debugging
        return contacts

    # Update the contacts list in the JSON file and send an update request to the server
    def updateContacts(self):
        with open('contacts.json', 'w') as output:
            output.write(json.dumps([x.__dict__ for x in self.contacts]))
        self.socket.send("UPDATE CONTACTS".encode())
        self.sendToServer()

    # Handle the addition of a new contact, update the contact if it already exists
    def addContact_handle(self):
        name = input('Enter Full Name: ')
        email = input('Enter Email Address: ')

        with open("user.json", "r") as file:
            data = json.load(file)

        encrypted_name = crypto.Encrypt(name, data["password"], data["salt"])
        encrypted_email = crypto.Encrypt(email, data["password"], data["salt"])

        if self.contacts is not None:
            for contact in self.contacts:
                if contact.email == encrypted_email or contact.name == encrypted_name:
                    contact.name = encrypted_name
                    contact.email = encrypted_email
                    print("Contact Already Exists. Updating contact information.")
                    break
            else:
                self.contacts.append(User(encrypted_name, encrypted_email))
                print("Contact Added.")
                self.updateContacts()

    # Request the server to list the contacts and print the received data
    def listContacts_handle(self):
        self.socket.send("LIST CONTACTS".encode())
        msg = pickle.dumps(self.user)
        try:
            self.socket.send(msg)
        except ssl.SSLError as e:
            print(f"SSL error occurred: {e}")
        data = self.socket.recv(2048)
        while select.select([self.socket], [], [], 0)[0]:
            more_data = self.socket.recv(2048)
            data += more_data

        with open("user.json", "r") as file:
            user_data = json.load(file)
        data = data.decode()
        data = crypto.Decrypt(data, user_data["password"], user_data["salt"])

        print(data)
        return

    # Handle the sending of a file to a recipient
    def sendMessage_handle(self, recipient, filePath):
        if os.path.exists(filePath) is False:
            print('File does not exist.')
            return
        self.socket.send("SEND".encode())
        msg = pickle.dumps(self.user)
        self.socket.send(msg)

        msg = pickle.dumps(recipient)
        self.socket.send(msg)

        data = self.socket.recv(2048)
        response = data.decode('utf-8')

        if response == 'BUSY':
            print('Recipient is busy. Try again later.')
            return
        elif response == 'ERROR':
            print('File Send Failed. Recipient was not found online or in contacts.')
            return
        elif response == 'ACCEPTED':
            print('Recipient found. Contact has accepted the file transfer.')
            self.socket.send("REQ CERT".encode())
            cert = self.socket.recv(4096)

            self.sendFile(filePath, cert)
        elif response == 'REJECTED':
            print('Recipient found. Contact has rejected the file transfer.')
            return
        else:
            print("Error: Response not recognized.")

    # Send a file to a recipient
    def sendFile(self, filePath, cert):
        print('Sending File... (sendFile() method)')
        encrypted_key_and_data = crypto.encryptFile(filePath, cert)
        pickled_data = pickle.dumps(encrypted_key_and_data)

        # Send the encrypted data
        self.socket.send("SEND FILE".encode())
        self.socket.send(len(pickled_data).to_bytes(4, byteorder='big'))
        self.socket.send(os.path.basename(filePath).encode())
        self.socket.sendall(pickled_data)

        data = self.socket.recv(2048)
        response = data.decode('utf-8')
        if response == 'RECEIVED':
            print('File Sent Successfully.')
            
        

                
    # Handle the receiving of a file from a sender
    def receiveMessage_handle(self):
        print('Waiting for incoming messages...')

        with open("clientKeys/certificate.pem", "r") as file:
            cert = file.read()

        response = self.socket.recv(2048).decode('utf-8')
        if response != "FILE":
            return

        sender_data = self.socket.recv(2048)
        sender = pickle.loads(sender_data)
        prompt = input(f"Contact {sender.name} <{sender.email}> wants to send you a file. Do you accept (y/n)? ").lower()

        if prompt != 'y':
            self.socket.send("REJECT".encode())
            print('File Transfer Rejected.')
            return

        print('File Transfer Accepted. Receiving File...')
        self.socket.send("ACCEPT".encode())

        response = self.socket.recv(2048).decode('utf-8')
        if response != "CERT":
            print(f"Error: Expected CERT message from server but got {response}.")
            return
        self.socket.send("SEND CERT".encode())

        self.socket.send(cert.encode())

        response = self.socket.recv(2048).decode('utf-8')
        if response != "RECEIVED FILE":
            print(f"Error: Expected RECEIVED FILE message from server but got {response}.")
            return
        
        
        print("ENCRYPTED FILE RECEIVED") # debugging
        encrypted_data_len = int.from_bytes(self.socket.recv(4), byteorder='big')
        file_path = self.socket.recv(2048).decode('utf-8')
        pickled_data = b''
        while len(pickled_data) < encrypted_data_len:
            to_read = encrypted_data_len - len(pickled_data)
            pickled_data += self.socket.recv(4096 if to_read > 4096 else to_read)

        encrypted_key_and_data = pickle.loads(pickled_data)

        #encrypted_data = encrypted_data.decode()
        original_data = crypto.decryptFile(encrypted_key_and_data)

        # Write the decrypted data to a file
        with open(file_path, 'wb') as file:
            file.write(original_data)

        print(f'File Received Successfully: {file_path} - {len(original_data)} bytes')
        self.socket.send("RECEIVED FILE".encode())

    # This function creates a new SSL socket, sets socket options, and wraps it with SSL.
    def createSSLSocket(self):
        try:
        # Create a new socket object
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            # Allow reuse of addresses
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            # Wrap the socket with SSL
            sock = ssl.wrap_socket(
                sock, 
                keyfile=self.key_file, 
                certfile=self.cert_file, 
                ssl_version=ssl.PROTOCOL_TLSv1_2
            )

            print("Socket created successfully ...")
            return sock

        except socket.error as error:
            print(f"Socket creation failed with error code: '{error}'")
    
    # This function handles the start of the application. It checks if a user is registered,
    # prompts for user registration if not, and establishes a secure connection with the server.
    # It also verifies the client and server using a nonce.
    def startApp_handle(self):
        if self.user is None:
            prompt = input('No users are registered with this client.\nDo you want to register a new user (y/n)? ').lower()
            
            if prompt == 'y':
                self.createNewUser()
            else:
                print('Exiting SecureDrop.')
                exit()
        self.socket.connect((self.connect_to_host, self.connect_to_port))
        self.socket.send("LOGIN".encode())
        self.sendToServer()

        #VERIFY CONNECTION W NONCE
        self.socket.send("VERIFY LOGIN".encode())
        with open("clientKeys/certificate.pem", "r") as file:
            cert = file.read()
        self.socket.send(cert.encode())
        EncNonce = self.socket.recv(2048)
        with open("clientKeys/key.pem", "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )

        # Decrypt the data
        nonce = private_key.decrypt(
            EncNonce,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        self.socket.send(nonce)
        response = self.socket.recv(2048).decode('utf-8')
        if response != "CLIENT VERIFIED":
            print(f"Error: Expected CLIENT VERIFIED message from server but got {response}.")
            exit(1)
        else:
            self.socket.send("VERIFY SERVER".encode())
            serverCert = self.socket.recv(4096)
            cert_obj = x509.load_pem_x509_certificate(serverCert, default_backend())
            public_key = cert_obj.public_key()
            nonce = secrets.token_bytes(16)
            encrypted_nonce = public_key.encrypt(
                nonce,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            self.socket.send(encrypted_nonce)
            response = self.socket.recv(2048)
            if response == nonce:
                print("Server verified")
            else:
                print("Server not verified. Suspicious activity detected. Exiting.")
                exit(1)


        print('Welcome to SecureDrop.\nType "help" for commands.\n')
        self.mainMenu()

    # This function handles the main menu of the application. It provides a command line interface
    # for the user to interact with the application. It supports commands like 'add', 'list', 'send',
    # 'receive', 'exit', and 'help'.
    def mainMenu(self):

        commands = {
            'add': self.addContact_handle,
            'list': self.listContacts_handle,
            'send': self.sendMessage_handle,
            'receive': self.receiveMessage_handle,
            'exit': self.logoutUser,
            'help': self.printHelp
        }

        while True:
            prompt = input('secure_drop> ').split(' ')
            command = prompt[0].lower()

            if command in commands:
                if command == 'send':
                    if len(prompt) < 3:
                        print('Usage: send <contact> <filepath>')
                    else:
                        recipient = prompt[1]
                        filePath = prompt[2]
                        commands[command](recipient, filePath)
                else:
                    commands[command]()
            else:
                print('Invalid Command. Type "help" for commands.\n')

            if command == 'exit':
                print('Logging Out.')
                break

    # This function prints the help information for the application. It lists all the available commands
    # and their descriptions.
    def printHelp(self):
        print('\t"add" -> Add a contact\n\t"list" -> List all contacts\n\t"send" -> Send a message\n\t"receive" -> Receive a message\n\t"exit" -> Exit SecureDrop')
            

