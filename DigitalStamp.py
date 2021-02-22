from DigitalEnvelopeText import DigitalEnvelopeText
from DigitalSignature import DigitalSignature
from Convert import Convert

class DigitalStamp:
    def create(msg, publicKeyB, privateKeyA, secretKey, mode, hash):
        # Kreiram digitalnu omotnicu za tajnost
        C1, C2 = DigitalEnvelopeText.encrypt(msg, publicKeyB, secretKey, mode)
        # Kreiram digitalni potpis za integritet i autentičnost
        C3 = DigitalSignature.sign((C1+C2), privateKeyA, hash)
        # Fja šalje to kao tuple jer nema definiranog oblika tekstualne datoteke za Digitalni pečat!
        return (C1, C2, C3)

    def open(C1, C2, C3, privateKeyB, publicKeyA, publicKeyB, mode):
        msg = DigitalEnvelopeText.decrypt("DE.txt", publicKeyB, privateKeyB, mode)
        valid = DigitalSignature.check(publicKeyA, "DS.txt")
        return (msg, valid)


# Test - KORISTIM ISTI PUBLIC KEY I PRIVATE KEY ZA POŠILJATELJA I PRIMATELJA
# C1, C2, C3 = DigitalStamp.create(b"poruka", "RSA_publicKey.txt", "RSA_privateKey.txt", "DES_secretKey.txt", "OFB", "SHA512")
# print(DigitalStamp.open(C1, C2, C3, "RSA_privateKey.txt", "RSA_publicKey.txt", "RSA_publicKey.txt", "OFB"))
