import os
import logging
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from encryption import Encryption 
from datetime import datetime, timezone, timedelta
from json_manager import Json 
from cryptography.hazmat.primitives.asymmetric import rsa


class Servers:

    def __init__(self, name: str):
        self.name = name
        self.key_directory = f"{self.name}_server_keys"
        os.makedirs(self.key_directory, exist_ok=True)
        self.private_key, self.public_key = self._generate_and_save_keys()

    def _generate_and_save_keys(self):
        private_key, public_key = Encryption.generate_keys()
        private_key_path = os.path.join(self.key_directory, f"{self.name}_privkey.pem")
        public_key_path = os.path.join(self.key_directory, f"{self.name}_publickey.pem")
        Encryption.save_private_key(private_key, private_key_path, self.name)
        Encryption.save_public_key(public_key, public_key_path, self.name)
        return private_key, public_key

    def issue_certificate(self, user_stored):
        try:
            user_name = user_stored['username']
            user_public_key_path = user_stored['public_key_path']

            # Cargar clave pública desde el archivo especificado en el JSON
            user_public_key = Encryption.load_public_key(user_public_key_path)

            # Crear sujeto e emisor
            subject = x509.Name(
                [
                    x509.NameAttribute(NameOID.COMMON_NAME, user_name),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "User Organization"),
                ]
            )
            issuer = x509.Name(
                [
                    x509.NameAttribute(NameOID.COMMON_NAME, self.name),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, self.name),
                ]
            )

            # Crear el certificado
            certificate = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(issuer)
                .public_key(user_public_key)
                .serial_number(x509.random_serial_number())
                .not_valid_before(datetime.now(timezone.utc))
                .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
                .sign(self.private_key, hashes.SHA256())
            )

            # Guardar el certificado
            cert_path = os.path.join(self.key_directory, f"{user_name}_certificate.pem")
            with open(cert_path, "wb") as cert_file:
                cert_file.write(certificate.public_bytes(serialization.Encoding.PEM))

            logging.info(f"Certificate issued for {user_name} and saved at {cert_path}")
            return certificate
        
        except FileNotFoundError:
            logging.error(f"Public key file for user not found at {user_stored.get('public_key_path')}")
            raise

    @staticmethod
    def create_servers_and_issue_certificates(servers: list, user: str):
        servers = ["colmena", "gafe", "toldos", "lagarto"]
        try:
            user_stored = Json.get_user_data(user)  # Obtener datos del usuario desde JSON
            server_instances = {name: Servers(name) for name in servers}
            for server_name, server in server_instances.items():
                server.issue_certificate(user_stored)
        except Exception as e:
            logging.error(f"An error occurred during certificate issuance: {e}")
            raise
class uc3m:

    def __init__(self, name="uc3m"):
        self.name = name
        self.key_directory = f"{self.name}_keys"
        os.makedirs(self.key_directory, exist_ok=True)
        self.private_key = self._generate_and_save_private_key()
        self.self_signed_cert = self._generate_self_signed_certificate()

    def _generate_and_save_private_key(self):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        # Guardar la clave privada en un archivo
        private_key_path = os.path.join(self.key_directory, f"{self.name}_privkey.pem")
        with open(private_key_path, "wb") as key_file:
            key_file.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),  # Sin contraseña
                )
            )

        print(f"Private key saved at {private_key_path}")
        return private_key

    def _generate_self_signed_certificate(self):
        # Detalles del certificado autofirmado
        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "uc3m Certification Authority"),
                x509.NameAttribute(NameOID.COMMON_NAME, "uc3m"),
            ]
        )

        # Crear el certificado
        certificate = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)  # Autofirmado: subject == issuer
            .public_key(self.private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))  # 10 años
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None), critical=True  # Es una CA
            )
            .sign(self.private_key, hashes.SHA256())  # Firma con la clave privada
        )

        # Guardar el certificado en un archivo
        cert_path = os.path.join(self.key_directory, f"{self.name}_self_signed_cert.pem")
        with open(cert_path, "wb") as cert_file:
            cert_file.write(certificate.public_bytes(serialization.Encoding.PEM))

        print(f"Self-signed certificate saved at {cert_path}")
        return certificate
