import os
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from cryptography.x509.oid import NameOID
from tkinter import messagebox

class CertificateAuthority:
    @staticmethod
    def create_ca(common_name, issuer_cert=None, issuer_key=None):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"ES"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"UC3M"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(subject)
        builder = builder.issuer_name(subject if issuer_cert is None else issuer_cert.subject)
        builder = builder.public_key(private_key.public_key())
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.not_valid_before(datetime.now())
        builder = builder.not_valid_after(datetime.now() + timedelta(days=3650))
        builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        certificate = builder.sign(private_key if issuer_key is None else issuer_key, hashes.SHA256())
        return private_key, certificate

    @staticmethod
    def save_cert_and_key(cert, key, cert_path, key_path):
        cert_dir = os.path.dirname(cert_path)
        key_dir = os.path.dirname(key_path)
        if cert_dir and not os.path.exists(cert_dir):
            os.makedirs(cert_dir, exist_ok=True)
        if key_dir and not os.path.exists(key_dir):
            os.makedirs(key_dir, exist_ok=True)
        with open(cert_path, "wb") as cert_file:
            cert_file.write(cert.public_bytes(Encoding.PEM))
        with open(key_path, "wb") as key_file:
            key_file.write(key.private_bytes(
                Encoding.PEM, 
                PrivateFormat.PKCS8, 
                NoEncryption()
            ))

    @staticmethod
    def verify_certificate_chain(cert_to_verify, issuer_cert):
        try:
            issuer_public_key = issuer_cert.public_key()

            print(f"Verifying certificate for: {cert_to_verify.subject}")
            print(f"Using issuer: {issuer_cert.subject}")
            print(f"Signature algorithm: {cert_to_verify.signature_hash_algorithm}")

            issuer_public_key.verify(
                cert_to_verify.signature,
                cert_to_verify.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert_to_verify.signature_hash_algorithm,
            )

            if not (cert_to_verify.not_valid_before <= datetime.now() <= cert_to_verify.not_valid_after):
                raise ValueError("El certificado ha expirado o aún no es válido.")
            
            if issuer_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value.lower() == "uc3m":
                issuer_public_key.verify(
                    issuer_cert.signature,
                    issuer_cert.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    issuer_cert.signature_hash_algorithm,
                )
                print(f"CA raíz ('UC3M') alcanzada y verificada, la cadena de certificados es válida.")
                messagebox.showinfo('Éxito', 'Certificado verificado con éxito.')
                return

            issuer_issuer_cert_path = f"CA/{issuer_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value.lower()}/{issuer_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value.lower()}_cert.pem"
            if not os.path.exists(issuer_issuer_cert_path):
                raise FileNotFoundError(f"Certificado del emisor de {issuer_cert.subject} no encontrado.")

            with open(issuer_issuer_cert_path, 'rb') as file:
                issuer_issuer_cert = x509.load_pem_x509_certificate(file.read())

            CertificateAuthority.verify_certificate_chain(issuer_cert, issuer_issuer_cert)
        except Exception as e:
            print(f"Error al verificar el certificado: {e}")
            messagebox.showerror('Error', f'Error al verificar el certificado: {e}')
            raise e

    @staticmethod
    def exchange_and_verify_certificate(user_a, user_b):
        user_a_cert_path = f"{user_a}_server/{user_a}_cert.pem"
        user_b_cert_path = f"{user_b}_server/{user_b}_cert.pem"

        if not os.path.exists(user_a_cert_path):
            raise FileNotFoundError(f"Certificate for {user_a} not found: {user_a_cert_path}")
        if not os.path.exists(user_b_cert_path):
            raise FileNotFoundError(f"Certificate for {user_b} not found: {user_b_cert_path}")

        with open(user_a_cert_path, 'rb') as file:
            user_a_cert = x509.load_pem_x509_certificate(file.read())
        with open(user_b_cert_path, 'rb') as file:
            user_b_cert = x509.load_pem_x509_certificate(file.read())

        def get_issuer_certificate_chain(cert):
            chain = []
            while True:
                issuer_string = cert.issuer.rfc4514_string()
                issuer_parts = dict(part.split('=') for part in issuer_string.split(','))
                organization = issuer_parts.get('CN').lower()
                issuer_cert_path = f"CA/{organization}/cert.pem"
                if not os.path.exists(issuer_cert_path):
                    raise FileNotFoundError(f"Issuer certificate for {cert.subject} not found: {issuer_cert_path}")
                with open(issuer_cert_path, 'rb') as file:
                    issuer_cert = x509.load_pem_x509_certificate(file.read())
                chain.append(issuer_cert)
                if organization == "uc3m":
                    break
                cert = issuer_cert
            return chain

        # Verificar la cadena de certificados para el usuario A
        issuer_chain_a = get_issuer_certificate_chain(user_a_cert)
        for i in range(len(issuer_chain_a) - 1):
            CertificateAuthority.verify_certificate_chain(issuer_chain_a[i], issuer_chain_a[i + 1])

        # Verificar la cadena de certificados para el usuario B
        issuer_chain_b = get_issuer_certificate_chain(user_b_cert)
        for i in range(len(issuer_chain_b) - 1):
            CertificateAuthority.verify_certificate_chain(issuer_chain_b[i], issuer_chain_b[i + 1])

        return user_a_cert.public_key(), user_b_cert.public_key()

def initialize_cas():
    os.makedirs("CA", exist_ok=True)
    root_key, root_cert = CertificateAuthority.create_ca("UC3M")
    os.makedirs("CA/uc3m", exist_ok=True)
    CertificateAuthority.save_cert_and_key(root_cert, root_key, "CA/uc3m/uc3m_cert.pem", "CA/uc3m/uc3m_key.pem")
    apartments = ["apartamentos_colmena", "apartamentos_lagarto", "apartamentos_gafe", "apartamentos_toldos"]
    for apartment in apartments:
        os.makedirs(f"CA/{apartment}", exist_ok=True)
        apartment_key, apartment_cert = CertificateAuthority.create_ca(apartment, issuer_cert=root_cert, issuer_key=root_key)
        CertificateAuthority.save_cert_and_key(apartment_cert, apartment_key, f"CA/{apartment}/cert.pem", f"CA/{apartment}/key.pem")

if __name__ == "__main__":
    initialize_cas()
