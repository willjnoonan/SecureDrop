import socket
from _thread import *
import ssl
from cryptoUtil import cryptoUtil
from client import User
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import secrets
import pickle

crypto = cryptoUtil()

class Server:
    # Initialize the server with default values
    def __init__(self):
        self.host = '127.0.0.1' 
        self.port = 52000
        self.key_file = "serverKeys/key.pem"
        self.cert_file = "serverKeys/certificate.pem"
        self.socket = self.createSSLSocket()
        self.connectedClients = []
        self.transfer = None

    # Create a new SSL socket
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

    # Start the server and listen for incoming connections
    def start(self):
        try:
            self.socket.bind((self.host, self.port))
        except socket.error as error:
            print("Socket binding failed with error code: '{0}'".format(error))
        print("Server started on port: {0}".format(self.port))
        self.socket.listen()
        while True:
            self.handleConnections()
    
    # Handle incoming connections
    def handleConnections(self):
        client, address = self.socket.accept()
        print("Connected to: {0}:{1}".format(address[0],str(address[1])))
        start_new_thread(self.processClientMessages, (client,))

    # Process incoming messages from a client
    def processClientMessages(self, conn):
        while True:
            msg = conn.recv(2048).decode('utf-8')

            print(f"Received message: {msg}")

            match msg:
                case "LOGOUT":
                    data = conn.recv(2048)
                    self.logout(data)
                    break
                case "LOGIN":
                    data = conn.recv(2048)
                    pkl = pickle.loads(data)
                    pkl.client = conn
                    self.connectedClients.append(pkl)
                case "VERIFY LOGIN":
                    clientCert = conn.recv(4096)
                    cert_obj = x509.load_pem_x509_certificate(clientCert, default_backend())
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
                    conn.send(encrypted_nonce)
                    response = conn.recv(2048)
                    if response == nonce:
                        print("Client verified")
                        conn.send("CLIENT VERIFIED".encode('utf-8'))
                    else:
                        print("Client not verified with server. Suspicous activity detected. Closing connection.")
                        conn.close()
                case "VERIFY SERVER":
                    with open("serverKeys/certificate.pem", "r") as file:
                        cert = file.read()
                    conn.send(cert.encode())
                    EncNonce = conn.recv(2048)
                    with open("serverKeys/key.pem", "rb") as key_file:
                        private_key = serialization.load_pem_private_key(
                            key_file.read(),
                            password=None,
                            backend=default_backend()
                        )
                    nonce = private_key.decrypt(
                        EncNonce,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
                    conn.send(nonce)
                case "UPDATE CONTACTS":
                    data = conn.recv(2048)
                    self.updateContacts(data)
                case "LIST CONTACTS":
                    data = conn.recv(2048)
                    response = self.listConnectedClients(data)
                    print(response) # debugging
                    conn.send(response)
                case "SEND":
                    self.checkUser(conn)
                case "SEND FILE":
                    fileSize = int.from_bytes(conn.recv(4), byteorder='big')
                    filePath = conn.recv(2048).decode('utf-8')
                    pickled_data = bytearray()
                    while fileSize > 0:
                        data = conn.recv(min(fileSize, 4096))
                        fileSize -= len(data)
                        pickled_data += bytearray(data)
                    self.transfer[1].client.send("RECEIVED FILE".encode('utf-8'))
                    self.transfer[1].client.send(len(pickled_data).to_bytes(4, byteorder='big'))
                    self.transfer[1].client.send(filePath.encode('utf-8'))
                    self.transfer[1].client.send(pickled_data)
                case "ACCEPT":
                    self.transfer[0].client.send("ACCEPTED".encode('utf-8'))
                case "REQ CERT":
                    self.transfer[1].client.send("CERT".encode('utf-8'))
                case "SEND CERT":
                    cert = conn.recv(4096)
                    self.transfer[0].client.send(cert)
                case "REJECT":
                    self.transfer[0].client.send("REJECTED".encode('utf-8'))
                    self.transfer = None
                case "RECEIVED FILE":
                    self.transfer[0].client.send("RECEIVED".encode('utf-8'))
                    self.transfer = None
                case _:
                    print(f"Unknown message: {msg}. Quitting...")
                    conn.close()
                    exit(1)
    
    # Handle a logout request from a client
    def logout(self, data):
        pkl = pickle.loads(data)
        print(self.connectedClients)
        for client in self.connectedClients:
            print(client.name) #debugging
            print(pkl.name) #debugging
            print(client.email) #debugging
            print(pkl.email) #debugging
            if client.name == pkl.name and client.email == pkl.name:
                print("Removing client")
                self.connectedClients.remove(client)
                return

    # Update the contacts of a client
    def updateContacts(self, data):
        print("Updating contacts") #debugging
        pkl = pickle.loads(data)
        for client in self.connectedClients:
            if client.name == pkl.name and client.email == pkl.email:
                client.contacts = pkl.contacts
                return

    # List the connected clients
    def listConnectedClients(self, data):
        pkl = pickle.loads(data)
        onlineUsers = "  The following contacts are online:"
        target = None

        # Create a dictionary mapping user names and emails to user objects
        user_dict = {(user.name, user.email): user for user in self.connectedClients}

        # Find the target user
        target = user_dict.get((pkl.name, pkl.email))

        if target is None:
            print("Error: Could not find target user with data " + pkl)
            return

        # Check every contact in sender's list
        for contact in target.contacts:
            name = crypto.Decrypt(contact.name, target.password, target.salt)
            email = crypto.Decrypt(contact.email, target.password, target.salt)
            

            # If the contact is online
            if self.isUserLoggedIn(name, email):
                # Find the contact's user object
                user = user_dict.get((name, email))

                if user:
                    for contact in user.contacts:
                        contactName = crypto.Decrypt(contact.name, user.password, user.salt)
                        contactEmail = crypto.Decrypt(contact.email, user.password, user.salt)

                        # If the sender's info is in the contact's list, add the contact to sender's list
                        if contactName == target.name and contactEmail == target.email:
                            onlineUsers += "\n  * {0} <{1}>".format(name, email)
                            break
        
        onlineUsers = crypto.Encrypt(onlineUsers, target.password, target.salt)
        return onlineUsers.encode()
         


    # Check if a user is valid    
    def checkUser(self, conn):
        print("Checking user")  # debugging
        sender, receiver = self.receiveData(conn)

        if self.transfer is not None:
            print("Transfer is not None")
            self.sendResponse(conn, "BUSY")
            return

        senderUser, receiverUser = self.findUsers(sender, receiver)

        if senderUser is None or receiverUser is None:
            print("ERROR")  # debugging
            self.sendResponse(conn, "ERROR")
            return

        isSenderAdded, isReceiverAdded = self.checkContacts(senderUser, receiverUser)

        if receiverUser and self.isUserLoggedIn(receiverUser.name, receiverUser.email) and isSenderAdded and isReceiverAdded:
            print("User is logged in and verified")  # debugging
            print("Sending file")
            self.sendResponse(receiverUser.client, "FILE")

            tempPkl = pickle.dumps(User(senderUser.name, senderUser.email))
            receiverUser.client.send(tempPkl)
            self.transfer = (senderUser, receiverUser)
        else:
            print("ERROR")  # debugging
            self.sendResponse(conn, "ERROR")

    # Receive data from a client
    def receiveData(self, conn):
        data = conn.recv(2048)
        sender = pickle.loads(data)
        data = conn.recv(2048)
        receiver = pickle.loads(data)
        print(sender)  # debugging
        print(receiver)  # debugging
        return sender, receiver

    # Send a response to a client
    def sendResponse(self, conn, message):
        conn.send(message.encode('utf-8'))

    # Find users in the connected clients list
    def findUsers(self, sender, receiver):
        senderUser = next((client for client in self.connectedClients if client.name == sender.name and client.email == sender.email), None)
        receiverUser = next((client for client in self.connectedClients if client.email == receiver), None)
        print(senderUser)  # debugging
        print(receiverUser)  # debugging
        return senderUser, receiverUser

    # Check if the contacts of two users are added to each other's list
    def checkContacts(self, senderUser, receiverUser):
        isSenderAdded = any(contact for contact in senderUser.contacts if self.isContactsAdded(contact, receiverUser, senderUser))
        isReceiverAdded = any(contact for contact in receiverUser.contacts if self.isContactsAdded(contact, senderUser, receiverUser))
        return isSenderAdded, isReceiverAdded

    # Check if a contact is added to a user's contact list
    def isContactsAdded(self, contact, user, current_user):
        contactEmail = crypto.Decrypt(contact.email, current_user.password, current_user.salt)
        contactName = crypto.Decrypt(contact.name, current_user.password, current_user.salt)
        if contactEmail == user.email and contactName == user.name:
            print(f"{user.name} Added")  # debugging
            return True
        return False

    # Check if a user is logged in
    def isUserLoggedIn(self, name, email):
        for user in self.connectedClients:
            if user.name == name and user.email == email:
                return True
        return False
