import base64
# For Encoding / Decoding the salt
from base64 import b64decode
# For Encrpyting / Decrpyting
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import Encoding
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend


# Util class for cryptography
class cryptoUtil():
    
    # Encrypts the given data using the provided password and salt
    def Encrypt(self, data, passwd, salt):
        data = data.encode('utf-8')
        password = passwd.encode('utf-8')
        salt = b64decode(salt)
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),
            length = 32,
            salt = salt,
            iterations = 450000
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        f = Fernet(key)
        token = f.encrypt(data)
        return token.decode('utf-8')

    # Decrypts the given data using the provided password and salt
    def Decrypt(self, data, passwd, salt):
        data = data.encode('utf-8')
        password = passwd.encode('utf-8')
        salt = b64decode(salt)
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),
            length = 32,
            salt = salt,
            iterations = 450000
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        f = Fernet(key)
        token = f.decrypt(data)
        return token.decode('utf-8')

      # Encrypts a file using a public key from a certificate  
    def encryptFile(self, filePath, cert):
        # Load the public key from the certificate
        cert_obj = x509.load_pem_x509_certificate(cert, default_backend())
        public_key = cert_obj.public_key()

        # Generate a symmetric key
        symmetric_key = Fernet.generate_key()
        cipher_suite = Fernet(symmetric_key)

        # Read the file data
        with open(filePath, 'rb') as file:
            data = file.read()

        encrypted_data = cipher_suite.encrypt(data)

        # Encrypt the data
        encrypted_key = public_key.encrypt(
            symmetric_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return (encrypted_key, encrypted_data)
    
    # Decrypts a file using a private key
    def decryptFile(self, encrypted_key_and_data):
        # Load the private key
        encrypted_key, encrypted_data = encrypted_key_and_data

        with open("clientKeys/key.pem", "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )

        # Decrypt the symmetric key with the private key
        symmetric_key = private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        # Use the symmetric key to decrypt the data
        cipher_suite = Fernet(symmetric_key)
        original_data = cipher_suite.decrypt(encrypted_data)
        
        return original_data

    def create_self_signed_cert(self, cert_path, key_path, key_size=4096, valid_days=365):
        # Generate a RSA private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size
        )

        # Generate a self-signed certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1"),
        ])
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=valid_days)
        ).sign(private_key, hashes.SHA256())

        # Write the certificate and private key to files
        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(Encoding.PEM))

        with open(key_path, "wb") as f:
            f.write(private_key.private_bytes(
                Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption()
            ))

    def create_cert_signed_by_ca(self, ca_cert_path, ca_key_path, cert_path, key_path, key_size=4096, valid_days=365):
        # Load the CA's private key
        with open(ca_key_path, "rb") as f:
            ca_private_key = serialization.load_pem_private_key(
                f.read(),
                password=None,
            )

        # Load the CA's certificate
        with open(ca_cert_path, "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read())

        # Generate a new private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
        )

        # Generate a certificate signing request (CSR)
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1"),
        ])).sign(private_key, hashes.SHA256())

        # Sign the CSR with the CA's private key to get a certificate
        cert = (
            x509.CertificateBuilder()
            .subject_name(csr.subject)
            .issuer_name(ca_cert.subject)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow())
            .not_valid_after(datetime.utcnow() + timedelta(days=valid_days))
            .sign(ca_private_key, hashes.SHA256())
        )

        # Write the certificate and private key to files
        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(Encoding.PEM))

        with open(key_path, "wb") as f:
            f.write(private_key.private_bytes(
                Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            ))

    # def generateEncryptedNonce(self, cert, nonce):
    #     cert_obj = x509.load_pem_x509_certificate(cert, default_backend())
    #     public_key = cert_obj.public_key()
    #     encrypted_nonce = public_key.encrypt(
    #         nonce,
    #         padding.OAEP(
    #             mgf=padding.MGF1(algorithm=hashes.SHA256()),
    #             algorithm=hashes.SHA256(),
    #             label=None
    #         )
    #     )
    #     return encrypted_nonce
    
    # def decryptNonce(self, encrypted_nonce, privKeyPath):
    #     with open(privKeyPath, "rb") as key_file:
    #         private_key = serialization.load_pem_private_key(
    #             key_file.read(),
    #             password=None,
    #             backend=default_backend()
    #         )

    #     # Decrypt the data
    #     nonce = private_key.decrypt(
    #         encrypted_nonce,
    #         padding.OAEP(
    #             mgf=padding.MGF1(algorithm=hashes.SHA256()),
    #             algorithm=hashes.SHA256(),
    #             label=None
    #         )
    #     )
    #     return nonce, encrypted_nonce

        


