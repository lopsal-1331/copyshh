import os
from encryption import Encryption  
from cryptography import x509 
from cryptography.x509.oid import NameOID  
from cryptography.hazmat.primitives import hashes, serialization  
from datetime import datetime, timezone, timedelta  
from cryptography.hazmat.primitives.asymmetric import rsa 

# class uc3m, root CA
class Uc3m: 
    def __init__(self, name='uc3m'):
        self.name = name  # entity name
        self.key_directory = f'{self.name}_keys'  # server for entity
        os.makedirs(self.key_directory, exist_ok=True)  # creates the server if it does not exist
        self.private_key = self._generate_and_save_private_key()  # generates and saves privavte key
        self.self_signed_cert = self._generate_self_signed_certificate()  # generates self signed certificate
    
    # method to generate and save the private key for root CA
    def _generate_and_save_private_key(self): 
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)  # generate rsa key
        private_key_path = os.path.join(self.key_directory, f'{self.name}_privkey.pem') 
        with open(private_key_path, 'wb') as key_file: 
            key_file.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,  
                    format = serialization.PrivateFormat.TraditionalOpenSSL,  
                    encryption_algorithm=serialization.NoEncryption(), 
                )
            )
        return private_key  

    # method to generate the self-signed certificate of CA
    def _generate_self_signed_certificate(self):
        # define subject and issuer, in this case they are both the same
        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'UC3M Certification Authority'),  
                x509.NameAttribute(NameOID.COMMON_NAME, 'uc3m')  
            ]
        )

        # constructs the certificate using the private key + signature
        certificate = (
            x509.CertificateBuilder()
            .subject_name(subject)  
            .issuer_name(issuer)  
            .public_key(self.private_key.public_key())  # uses public key of CA
            .serial_number(x509.random_serial_number())  # random serial number
            .not_valid_before(datetime.now(timezone.utc))  
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=3650))  # valid for 10 years
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)  # root certificate signal
            .sign(self.private_key, hashes.SHA256())  # signed with private key of CA
        )
        # saves certificate in a sevrer
        cert_path = os.path.join(self.key_directory, f'{self.name}_self_signed_cert.pem')
        with open(cert_path, 'wb') as cert_file:
            cert_file.write(certificate.public_bytes(serialization.Encoding.PEM))
        return certificate  # returns the self signed certificate

# Class 'Servers' to represent the servers to be validated by uc3m root CA
class Servers: 
    uc3m_instance=None 
    servers_instances={}

    def __init__(self, name:str, root_ca=None): 
        self.name = name  # Nombre del servidor
        self.key_directory = f'{self.name}_server_keys'  
        os.makedirs(self.key_directory, exist_ok=True)  
        self.private_key, self.public_key = self._generate_and_save_keys()  
        # if a root ca is passed, generates and saves the certificate signed by them
        self.certificate = self._generate_and_save_certificate_signed_by_ca(root_ca) if root_ca else None

    # method to generate and save the public and private keys of the server
    def _generate_and_save_keys(self):
        private_key, public_key = Encryption.generate_keys()  # generates rsa keys
        # saves pem key files in servers directories
        Encryption.save_private_key(private_key, os.path.join(self.key_directory, f'{self.name}_privkey.pem'), self.name)
        Encryption.save_public_key(public_key, os.path.join(self.key_directory, f'{self.name}_publickey.pem'), self.name)
        return private_key, public_key  # returns the keys generated
    
    def create_and_sign_csr(self, username, user_public_key):
        # Crear una solicitud de firma de certificado (CSR) para el usuario
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, f'{username}')]))  # Nombre del usuario
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)  # No es un certificado CA
            .sign(self.private_key, hashes.SHA256())  # Firmar el CSR con la clave privada del servidor
        )

        # Ahora firmar el CSR con la CA del servidor
        certificate = (
            x509.CertificateBuilder()
            .subject_name(csr.subject)  # Usar el sujeto del CSR
            .issuer_name(self.certificate.subject)  # El emisor es el certificado del servidor
            .public_key(user_public_key)  # Usar la clave pública del usuario
            .serial_number(x509.random_serial_number())  # Número de serie único
            .not_valid_before(datetime.now(timezone.utc))  # El certificado es válido desde ahora
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=3650))  # El certificado es válido por 10 años
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)  # No es un certificado CA
            .sign(self.private_key, hashes.SHA256())  # Firmar el certificado con la clave privada del servidor
        )

        return certificate  # Devolver el certificado firmado
    
    # method to generate and save the certificate signed by root ca
    def _generate_and_save_certificate_signed_by_ca(self, root_ca):
        # defines subject - common name of server
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, self.name)])
        # generates the certificate using public key of server and private key of root CA
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)  
            .issuer_name(root_ca.self_signed_cert.subject)  
            .public_key(self.public_key)  
            .serial_number(x509.random_serial_number())  
            .not_valid_before(datetime.now(timezone.utc))  
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=3650))  
            .sign(root_ca.private_key, hashes.SHA256())  
        )
        # saves signed certificate in file
        cert_path = os.path.join(self.key_directory, f'{self.name}_certificate.pem')
        with open(cert_path, 'wb') as cert_file:
            cert_file.write(cert.public_bytes(serialization.Encoding.PEM))
        return cert 

    # method to start root CA and servers
    @classmethod
    def initialize_authorities(cls):
        if not cls.uc3m_instance:  # if theres no root CA instance
            cls.uc3m_instance = Uc3m()  # creates instance
            # create instances and generate their certificates
            cls.servers_instances = {
                name: Servers(name, cls.uc3m_instance)  # create and asign certificates
                for name in ["apartamentos_colmena", "apartamentos_gafe", "apartamentos_toldos", "apartamentos_lagarto"]
            }

