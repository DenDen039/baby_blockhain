from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature


class KeyPair(object):
    def __init__(self) -> None:
        self._private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048,)
        self.public_key = self._private_key.public_key()

    def bytes_presentation(self):
        private_pem = self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption())
        public_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        return private_pem, public_pem

    def printKeyPair(self):
        private_pem, public_pem = self.bytes_presentation()
        print("private key:", private_pem)
        print("public key:", public_pem)

    def __str__(self) -> str:
        private_pem, public_pem = self.bytes_presentation()
        return str(private_pem)+" "+str(public_pem)

    @classmethod
    def genKeyPair(cls):
        return KeyPair()


class Signature(object):
    @classmethod
    def signData(cls, private_key, message):
        return private_key.sign(message,
                                padding.PSS
                                (
                                    mgf=padding.MGF1(hashes.SHA256()),
                                    salt_length=padding.PSS.MAX_LENGTH
                                ),
                                hashes.SHA256())

    @classmethod
    def verifySignature(cls, message, public_key, signature):
        verification = True
        try:
            public_key.verify(signature, message,
                              padding.PSS
                              (
                                  mgf=padding.MGF1(hashes.SHA256()),
                                  salt_length=padding.PSS.MAX_LENGTH
                              ),
                              hashes.SHA256()
                              )
        except InvalidSignature:
            verification = False
        return verification


if __name__ == "__main__":
    keys = KeyPair.genKeyPair()
    keys.printKeyPair()
    bytes = Signature.signData(keys._private_key, b"Hello world!")
    print(Signature.verifySignature(b"Hello world!", keys.public_key, bytes))
