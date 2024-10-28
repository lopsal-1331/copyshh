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


class Encryption: 
    @staticmethod
    def get_token_salt(pas, salt):
        if salt is None: 
            salt=os.urandom(16)
        pas = pas.encode('utf-8')
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
        key=Fernet.generate_key()
        with open('global_server/clave.key', 'wb') as key_file: 
            key_file.write(key)
    
    @staticmethod
    def get_database_key():
        try: 
            with open('global_server/clave.key', 'rb') as file: 
                return file.read()
        except FileNotFoundError: 
            Encryption.generate_fernet_key()
            with open('global_server/clave.key', 'rb') as file: 
                return file.read()
    
    @staticmethod
    def encrypt_fernet(data:str)->bytes: 
        key=Encryption.get_database_key()
        fernet=Fernet(key)
        encrypted_data=fernet.encrypt(data.encode())
        return encrypted_data

    @staticmethod 
    def decrypt_fernet(edata:bytes)->str: 
        key=Encryption.get_database_key()
        fernet=Fernet(key)
        decrypted_data=fernet.decrypt(edata).decode()
        return decrypted_data

    @staticmethod
    def generate_keys():
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        return private_key, public_key

    @staticmethod
    def save_private_key(private_key, filename: str, user: str, password: bytes = None):
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
        filepath = filename  # Can also add user folder logic if necessary
        
        with open(filepath, 'rb') as keyfile: 
            pem = keyfile.read()
        
        public_key = serialization.load_pem_public_key(pem)
        return public_key
    
    @staticmethod
    def rsa_encrypt(public_key, message):
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
        chacha_key = os.urandom(32)  # Genera una clave de 256 bits para ChaCha20
        four_digit_code = str(random.randint(1000, 9999)).encode('utf-8')  # Genera un código de 4 cifras
        return chacha_key, four_digit_code

    @staticmethod
    def save_chacha_key(user, chacha_key, room_code): 
        chacha_key_path=f'{user}_server/{room_code}_key.bin'
        with open(chacha_key_path, 'wb') as file: 
            file.write(chacha_key)
        return True
    
    @staticmethod 
    def sign_invitation(priv_key, data:bytes):
        signature=priv_key.sign(
            data, 
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), 
                salt_length=padding.PSS.MAX_LENGTH
            ), 
            hashes.SHA256()
        )
        return signature
    
    @staticmethod
    def verify_signature(public_key, signature, data):
        try: 
            public_key.verify(
                signature, 
                data, 
                padding.PKCS1v15(), 
                hashes.SHA256()
            )
            return True
        except Exception as e: 
            print(f'Signature verification failed: {e}')
            return False

    @staticmethod
    def chacha_encrypt(key:bytes, data:bytes)->tuple:
        nonce=os.urandom(12)
        chacha=ChaCha20Poly1305(key)
        ctxt=chacha.encrypt(nonce, data, associated_data=None)
        return nonce, ctxt
    
    @staticmethod
    def chacha_decrypt(key:bytes, nonce:bytes, ctxt:bytes)->bytes:
        chacha=ChaCha20Poly1305(key)
        data=chacha.decrypt(nonce, ctxt, associated_data=None)
        return data
    
    @staticmethod 
    def save_encrypted_and_signed_data(encrypted_data, signature, filename1, filename2): 
        with open(filename1, 'wb') as f: 
            f.write(encrypted_data)
        with open(filename2, 'wb') as f: 
            f.write(signature)
        print('Encrypted data and signature saved.')

    @staticmethod
    def get_chacha_key(user, roomate, room_code):
        path = f'{user}_server/{roomate}_{room_code}_key.bin'
        if os.path.exists(path):
            with open(path, 'rb') as file: 
                chacha_key=file.read()
            return chacha_key
        else: 
            raise FileNotFoundError
    
    @staticmethod
    def rsa_sign(private_key, message):
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
    def generate_hmac_key(): 
        return os.urandom(32)
        
    @staticmethod
    def sign_with_hmac(hmac_key, message):
        # function to sign a message with hmac
        h = hmac.HMAC(hmac_key, hashes.SHA256())
        h.update(message)
        return h.finalize()

    @staticmethod
    def verify_hmac(key, text, signature): 
        # function to verify an hmac signature
        h=hmac.HMAC(key, hashes.SHA256())
        h.update(text)
        try: 
            h.verify(signature)
            return True
        except Exception as e: 
            return False