from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.serialization import load_pem_public_key

import requests
import logging
import sys
import getpass
import socketio

logging.basicConfig(filename='record.log', level=logging.DEBUG, format=f'%(asctime)s %(levelname)s %(filename)s %(funcName)s : %(message)s')
url = "https://127.0.0.1:5000/"

class Client:
    def __init__ (self):
        self.username = ""
        self.sessionKey = self.generateRSAKey()

    def generateRSAKey(self):
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        return key

    def getSignature(self, messageBinary):
        signature = self.sessionKey.sign(
            messageBinary,
                padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature


    def verifyMessage(self, message, signature):
        pass

    def decrypt(self, cipherText):
        plainText = self.sessionKey.decrypt(
            cipherText,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plainText

    def encrypt(self, messageBinary, publicKey):
        cipherText = publicKey.encrypt(
            messageBinary,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return cipherText.decode('latin1')

    def authPost(self, path, json):
        return requests.post(url + "/auth/" + path, data=json, verify="../server/cert.pem")

    def getUser(self):
        print("Username:")
        username = self.getInput()
        print("Password:")
        password = self.getInput(password=True)
        return username, password
    
    def hash(self, password):
        digest = hashes.Hash(hashes.SHA256())
        digest.update(password.encode())
        return digest.finalize().decode('latin1')

    def serializePublicKey(self):
        publicKey = self.sessionKey.public_key()
        publicKey = publicKey.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return publicKey.decode('latin1')

    def startup(self):
        logging.info("\n\n========== STARTING CLIENT ==========")
        loggedIn = False
        username = ""
        password = ""
        publicKey = self.serializePublicKey()
        print("Welcome to C02: The Message")
        uIn = self.intro()
        while loggedIn == False:
            if uIn in "lL":
                logging.info("Starting log in sequence")
                username, password = self.getUser()
            else:
                logging.info("Beginning registration sequence")
                username, password = self.getUser()

                print("Confirm:")
                confirm = self.getInput(password=True)

                while password != confirm:
                    print("Passwords do not match, please re-enter your password")
                    print("Password:")
                    password = self.getInput(password=True)
                    print("Confirm:")
                    confirm = self.getInput(password=True)

            logging.info(f"Username: {username}")
            password = self.hash(password)
            logging.info(f"Hashed Password: {password}")
            res = None
            if uIn in "rR":
                logging.info(f"Requesting registration of {username}")
                print("Registering...")
                res = self.authPost("register", {'username' : username, 'password' : password, 'publicKey' : publicKey})
            if res is None or res.ok:
                if res is not None:
                    logging.info(f"Successfully registered: {username}")
                logging.info(f"Requesting log in of {username}")
                print("Logging in...")
                res = self.authPost("login", {'username' : username, 'password' : password, 'publicKey' : publicKey})
            if res.ok == False:
                self.logError(res)
                uIn = self.intro()
            else:
                logging.info(f"Successfully logged in: {username}")
                self.username = username
                print(f"Success, welcome: {self.username}!")
                loggedIn = True

    def deleteAccount(self, sio):
        username = self.username
        logging.info(f"Beginning request to delete user: {username}")
        print("Please confirm your password")
        print("Password:")
        password = self.getInput(username, True)
        password = self.hash(password)
        logging.info(f"Hashed Password: {password}")
        res = self.authPost("delete", {'username' : username, 'password' : password})
        logging.info(f"Authentication request result: {res}")
        if res.ok:
            logging.info(f"Account deleted for {username}")
            print("Your account has been deleted")
            self.end(sio)
        else:
            self.logError(res)

    def logError(self, res):
        json = res.json()
        print(f"Error: {json['message']}")
        logging.info(f"Status code: {res.status_code} Message: {json['message']}")

    def intro(self):
        uIn = ""
        while True:
            print("Would you like to [L]ogin or [R]egister an account?")
            print("\t[L]ogin")
            print("\t[R]egister")
            print("\t[E]xit")
            uIn = self.getInput()
            if uIn in "YyEeLlRr":
                break
        if uIn in "Ee":
            self.end()
        return uIn

    def end(self, sio = None):
        print("\nExiting C02: Goodbye!")
        if sio is not None:
            sio.disconnect()
        sys.exit()
    
    def getInput(self, preamble = "", password = False):
        uIn = ""
        if password:
            uIn = getpass.getpass(f"{preamble}$ ")
        else:
            uIn = input(f"{preamble}$ ")
        print()
        return uIn
    
    def printFreeUsers(self):
        pass

sio = socketio.Client()
http_session = requests.Session()
http_session.verify = '../server/cert.pem'
sio = socketio.Client(http_session=http_session)
targetPublicKey = None

@sio.on('target public key')
def onTargetPublicKey(json):
    logging.info(f"Received public key for target: {json['target']}")
    logging.info(f"Public key: {json['public key']}")
    global targetPublicKey
    logging.info(f"Storing public key for duration of chat")
    targetPublicKey = serialization.load_pem_public_key(json['public key'].encode('latin1'))

@sio.on('encrypted message')
def onEncryptedMsg(json):
    source = json['source']
    symKey = json['symKey']
    message = json['message']
    logging.info(f"Received encrypted message for <{client.username}>")
    logging.info(f"source: {source}")
    logging.info(f"symKey: {symKey}")
    logging.info(f"message: {message}")
    logging.info(f"Decrypting symmetric key using session key")
    symKey = client.decrypt(symKey.encode('latin1'))
    f = Fernet(symKey)
    logging.info(f"Decrypting message contents using symmetric key")
    message = f.decrypt(message.encode('latin1')).decode('latin1')
    logging.info(f"Decrypted message contents:")
    logging.info(f"source: {source}")
    logging.info(f"symKey: {symKey}")
    logging.info(f"message: {message}")
    print(f"\n{source}> {message}\n{client.username}$ ")

@sio.on('bad key')
def onBadKey(json):
    logging.error(f"Error on connect, message: {json['message']}")
    print(f"Error on connect, message: {json['message']}")
    logging.info(f"Disconnecting")
    sio.disconnect()

@sio.on('busy user')
def onBusyUser(json):
    logging.error(f"Error on message request, message: {json['message']}")
    print(f"Error on message request, message: {json['message']}")

@sio.event
def connect():
    logging.info(f"Successfully connected to server")

@sio.event
def connect_error(data):
    logging.info(f"Can't connect to server")

@sio.event
def disconnect():
    logging.info(f"Disconnected from the server")

uIn = "start"
user = ""
chatting = ""
client = Client()
client.startup()
user = client.username

sio.connect(url, auth={'username' : client.username, 'signature' : client.getSignature(client.username.encode('latin1')).decode('latin1')})
while uIn not in "eE":
    if chatting == "":
        print("Commands:")
        print("\t[C]hat with online <USER>")
        print("\t[D]elete account")
        print("\t[E]xit")
    uIn = client.getInput(user)
    logging.info(f"user input: {uIn}")
    if chatting == "":
        if uIn[0] in "cC":
            partner = uIn[2:]
            print(f"You are now chatting with: {partner}")
            print(f"To stop chatting, type: !exit")
            chatting = partner
            json = {'source': client.username, 'target' : partner, 'signature' : client.getSignature(partner.encode('latin1')).decode('latin1')}
            logging.info(f"Initialising message to server with the following payload:")
            logging.info(f"jso: {json}")
            sio.emit('init msg', json)
        elif uIn in "dD":
            client.deleteAccount()
        elif uIn in "eE":
            client.end(sio)
    elif uIn == "!exit":
        logging.info(f"Ending chat with user")
        logging.info(f"chatting: {chatting}")
        logging.info(f"targetPublicKey: {targetPublicKey}")
        logging.info(f"Clearing contents...")
        chatting = ""
        targetPublicKey = None
        logging.info(f"chatting: {chatting}")
        logging.info(f"targetPublicKey: {targetPublicKey}")
    else:
        logging.info(f"Sending message to <{chatting}>")
        logging.info(f"Message: {uIn}")
        symKey = Fernet.generate_key()
        logging.info(f"Symmetric Key: {symKey.decode('latin1')}")
        f = Fernet(symKey)
        message = f.encrypt(uIn.encode('latin1'))
        message = message.decode('latin1')
        symKey = targetPublicKey.encrypt(symKey, 
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
        ))
        logging.info(f"Encrypting message and symmetric key")
        signature = client.getSignature(symKey).decode('latin1')
        symKey = symKey.decode('latin1')
        logging.info(f"Message: {message}")
        logging.info(f"Symmetric Key: {symKey}")
        logging.info(f"Sending message with the following payload:")
        json = {'source': client.username, 'target': chatting, 'message': message, 'symKey': symKey, 'signature': signature}
        logging.info(f"json: {json}")
        sio.emit("send message", json)
