import base64
import os
import random
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.backends import default_backend
from cryptography import x509


class Encryption: 
    @staticmethod
    def get_token_salt(pas, salt):
        # generates token and salt for a user using their password
        # if no salt given, generates a random byte sequence of 16
        if salt is None: 
            salt=os.urandom(16)
        # encode password
        pas = pas.encode('utf-8')
        # derive the key using hashes.sha254()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480000,
                )
        token = base64.urlsafe_b64encode(kdf.derive(pas))
        return token, salt     
    
    @staticmethod
    def generate_fernet_key():
        # generates a fernet key and saves it in the global server. only server has access to it
        key=Fernet.generate_key()
        with open('global_server/clave.key', 'wb') as key_file: 
            key_file.write(key)
    
    @staticmethod
    def get_database_key():
        # returns the fernet key from the server. Only the global server can use this function.
        try: 
            with open('global_server/clave.key', 'rb') as file: 
                return file.read()
        except FileNotFoundError: 
            Encryption.generate_fernet_key()
            with open('global_server/clave.key', 'rb') as file: 
                return file.read()
    
    @staticmethod
    def encrypt_fernet(data:str)->bytes: 
        # encrypt data using fernet
        key=Encryption.get_database_key()
        fernet=Fernet(key)
        encrypted_data=fernet.encrypt(data.encode())
        return encrypted_data

    @staticmethod 
    def decrypt_fernet(edata:bytes)->str: 
        # decrypts data using fernet
        key=Encryption.get_database_key()
        fernet=Fernet(key)
        decrypted_data=fernet.decrypt(edata).decode()
        return decrypted_data

    @staticmethod
    def generate_keys():
        # generates private and public key for a user when they log in 
        # private derives from the private key
        # public key is also saved in the open server
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        return private_key, public_key

    @staticmethod
    def save_private_key(private_key, filename: str, user: str, password: bytes = None):
        # function that saves the private key in a .pem file in the user server
        encryption_algorithm = serialization.NoEncryption()
        if password is not None: 
            encryption_algorithm = serialization.BestAvailableEncryption(password)
        
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM, 
            format=serialization.PrivateFormat.TraditionalOpenSSL, 
            encryption_algorithm=encryption_algorithm
        )
        
        folder_name = f"{user}_server"
        if not os.path.exists(folder_name):
            os.makedirs(folder_name)

        
        with open(filename, 'wb') as keyfile: 
            keyfile.write(pem)
    
    @staticmethod
    def save_public_key(public_key, filename: str, user: str):
        # function that saves the public key in the user server and global server
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM, 
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        folder_name = f"{user}_server"
        if not os.path.exists(folder_name):
            os.makedirs(folder_name)


        with open(filename, 'wb') as keyfile: 
            keyfile.write(pem)
    
    @staticmethod
    def load_private_key(filename: str, password: bytes = None):
        # gets private key from .pem file
        filepath = filename  # Can also add user folder logic if necessary
        
        with open(filepath, 'rb') as keyfile: 
            pem = keyfile.read()
        
        private_key = serialization.load_pem_private_key(
            pem, 
            password=password
        )
        
        return private_key

    @staticmethod
    def load_public_key(filename: str): 
        #  loads the public key from a .pem file
        filepath = filename 
        
        with open(filepath, 'rb') as keyfile: 
            pem = keyfile.read()
        
        public_key = serialization.load_pem_public_key(pem)
        return public_key
    
    @staticmethod
    def rsa_encrypt(public_key, message):
        # function to encrypt data using the public key of a user
        # use of padding, hash.sha256 algorithm
        return public_key.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    
    @staticmethod
    def rsa_decrypt(private_key, ciphertext):
        # function to decrypt using a user's private key
        # same configurationm (padding and algorithm) than the encryption function
        return private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    
    @staticmethod
    def generate_chacha_key_and_code():
         # Generates a ChaCha Key of 256 bits 
        chacha_key = os.urandom(32) 
        # random code of 4 numbers
        four_digit_code = str(random.randint(1000, 9999)).encode('utf-8')  
        return chacha_key, four_digit_code

    @staticmethod
    def save_chacha_key(user, chacha_key, room_code): 
        # saves the chacha key in a .bin file. usually found in user's server
        chacha_key_path=f'{user}_server/{room_code}_key.bin'
        with open(chacha_key_path, 'wb') as file: 
            file.write(chacha_key)
        return True

    @staticmethod
    def chacha_encrypt(key:bytes, data:bytes)->tuple:
        # encrypts using chachapoly data in bytes
        # returns both the encrypted data and nonce
        nonce=os.urandom(12)
        chacha=ChaCha20Poly1305(key)
        ctxt=chacha.encrypt(nonce, data, associated_data=None)
        return nonce, ctxt
    
    @staticmethod
    def chacha_decrypt(key:bytes, nonce:bytes, ctxt:bytes)->bytes:
        # decrypts data with a chacha key and a given nonce
        chacha=ChaCha20Poly1305(key)
        data=chacha.decrypt(nonce, ctxt, associated_data=None)
        return data
    
    @staticmethod 
    def save_encrypted_and_signed_data(encrypted_data, signature, filename1, filename2): 
        # function to save encrypted and signed data both in different files
        with open(filename1, 'wb') as f: 
            f.write(encrypted_data)
        with open(filename2, 'wb') as f: 
            f.write(signature)
        print('Encrypted data and signature saved.')

    @staticmethod
    def get_chacha_key(user, roomate, room_code):
        # loads the chacha key stored in the user server
        # each keyis identified by the room code and roomate username
        path = f'{user}_server/{roomate}_{room_code}_key.bin'
        if os.path.exists(path):
            with open(path, 'rb') as file: 
                chacha_key=file.read()
            return chacha_key
        else: 
            raise FileNotFoundError
    
    @staticmethod
    def rsa_sign(private_key, message):
        # function to sign a message using the private key of the user
        signature= private_key.sign(
            message, 
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature

    @staticmethod 
    def rsa_verify(public_key, message, signature):
        # function to verify a signature using the public key of the person who supposedly signed it
        try: 
            public_key.verify(
                signature, 
                message, 
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ), 
                hashes.SHA256()
            )
            return True
        except Exception as e: 
            return False
    
    @staticmethod
    def load_certificate(cert_path): 
        # method to load a .pem certificate from file 
        try: 
            # open cert file
            with open(cert_path, 'rb') as cert_file: 
                cert_data = cert_file.read()
            certificate = x509.load_der_x509_certificate(cert_data)
            return certificate
        except FileNotFoundError: 
            raise FileNotFoundError(f'Certificate file not found: {cert_path}')
        except Exception as e: 
            raise ValueError('Failed to load certificate.')
