from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5, PKCS1_OAEP
from Convert import Convert
from HelpFunction import HelpFunctions
import base64

class DigitalSignature:

    def sign(msg, privateKey, hash):
        privateKeyDict = Convert.TxtToDict(privateKey)
        n = int(privateKeyDict['Modulus'], 16)
        d = int(privateKeyDict['Private exponent'], 16)
        sendV = int(HelpFunctions.getHash(msg, hash).hex(), 16)
        M = pow(sendV, d, n)
        # M = DigitalSignature.encryptRSA(n, d, HelpFunctions.getHash(msg, hash))
        keyLengths = HelpFunctions.getHashLength(hash) + "\n    " + privateKeyDict['Key length']
        methods = hash + "\n    " + "RSA"

        # promjena jest što uključujem i poruku u digitalni potpis ('Message': M.hex())
        dict = {
            'Description': 'Signature',
            'File name': 'ds.txt',
            'Method': methods,
            'Key length': keyLengths,
            'Signature': hex(M),
            'Message': base64.b64encode(msg).decode("utf-8")
        }
        file = open('DS.txt', "w")
        file.write(Convert.DictToStr(dict))
        hexSinglFix = hex(M) # Singleton problem se javljao
        if len(hexSinglFix) % 2 != 0:
            hexSinglFix = "0"+hex(M)
        # print(hex(M)[2:])
        return bytes.fromhex(hexSinglFix[2:])
        
    def check(publicKey, ds):
        dsDict = Convert.TxtToDict(ds)
        publicKeyDict = Convert.TxtToDict(publicKey)
        msg = base64.b64decode( dsDict['Message'].encode('utf-8'))
        hashString = dsDict['Method'][0:-3]
        hash = HelpFunctions.getHash(msg, hashString)
        n = int(publicKeyDict['Modulus'], 16)
        e = int(publicKeyDict['Public exponent'], 16)
        sign = int(bytes.fromhex(dsDict['Signature'][2:]).hex(), 16)

        return hash == bytes.fromhex(hex(pow(sign, e, n))[2:])

# Test - sve radi, za svaki hash, ključ za RSA se određuje sa datotekom 
# DigitalSignature.sign(b"Poruka", "RSA_privateKey.txt", "SHA384")
# print(DigitalSignature.check("RSA_publicKey.txt", "DS.txt"))