from Crypto.Cipher.PKCS1_OAEP import PKCS1OAEP_Cipher
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import random
from Crypto.Signature import PKCS1_v1_5

from playground.crypto import X509Certificate

message = '1234567890qwertyuiop[]asdfghjkl;zxcvbnm,./'
with open("./keys/private.key") as f:
    priKeyData = f.read()
priKey = RSA.importKey(priKeyData)
with open("./keys/wli_signed.cert") as f:
    myCertData = f.read()
myCert = X509Certificate.loadPEM(myCertData)
with open("./keys/wenjunli_signed.cert") as f:
    CACertData = f.read()
CACert = X509Certificate.loadPEM(CACertData)
with open("./keys/20164_signed.cert") as f:
    rootCertData = f.read()
rootCert = X509Certificate.loadPEM(rootCertData)
nonce = random.randint(0, 65535)
print(nonce)

# ------------------------------------
# sign msg:client
rsaSigner = PKCS1_v1_5.new(priKey)
clienHasher = SHA256.new()
clienHasher.update(str(nonce))
signedMsg = rsaSigner.sign(clienHasher)
print "signature"
print signedMsg

c = X509Certificate.loadPEM(CACertData)
p = c.getPublicKeyBlob()
pk = RSA.importKey(p)
print type(pk)
print type(myCert)
# data = c.getPemEncodedCertWithoutSignatureBlob()
res = PKCS1_v1_5.new(pk).verify(SHA256.new(str(nonce)), signedMsg)
print res

# client send OPTIONS:nonce, myCert, CACert
# and signedMsg in signature

# ------------------------------------
# 1.client send nonce1, his cert(myCert), CA cert, here server do
# print myCert.getSubject()["commonName"] == self.transport.getPeer()[0]

# 2.check myCert sign is the CA:server
if myCert.getIssuer() != CACert.getSubject():
    print "wrong:"

# 3.use public key in CAcert to check client cert:server
CAPublickKeyBlock = CACert.getPublicKeyBlob()
CAPublicKey = RSA.importKey(CAPublickKeyBlock)
# clientPublicKeyBlock = myCert.getPublicKeyBlob()
# clientPublicKey = RSA.importKey(clientPublicKeyBlock)
# clientPublicKey == CAPublicKey: True
CAVerifier = PKCS1_v1_5.new(CAPublicKey)
hasher = SHA256.new()
data = myCert.getPemEncodedCertWithoutSignatureBlob()
hasher.update(data)
CAResult = CAVerifier.verify(hasher, myCert.getSignatureBlob())
print CAResult

# 4.check CAcert sign is the root:server
if CACert.getIssuer() != rootCert.getSubject():
    print 'rootwrong:'
rootPublicKeyBlock = rootCert.getPublicKeyBlob()
rootPublicKey = RSA.importKey(rootPublicKeyBlock)
rootVerifier = PKCS1_v1_5.new(rootPublicKey)
nhasher = SHA256.new()
CAdata = CACert.getPemEncodedCertWithoutSignatureBlob()
nhasher.update(CAdata)
rootResult = rootVerifier.verify(nhasher, CACert.getSignatureBlob())
print rootResult

# 5.client public key encrypt the nonce:server
clientPublicKeyEncrypter = PKCS1OAEP_Cipher(CAPublicKey, None, None, None)
EncNonce = clientPublicKeyEncrypter.encrypt(str(nonce))
print EncNonce

# 6.generate nonce1 to send
nonce1 = random.randint(0, 65535)
print(nonce1)
# server send OPTIONS: EncNonce, his cert(here myCert), his CACert(here CACert), nonce1



# client private key decryption:client
clientPriKeyDecrypter = PKCS1OAEP_Cipher(priKey, None, None, None)
rawNonce = clientPriKeyDecrypter.decrypt(EncNonce)
print rawNonce == str(nonce)

test = ''
if not test:
    print 'yes'

# verify sign:server
# tHasher = SHA256.new()
# tHasher.update(signedMsg)
# rs = CAVerifier.verify(tHasher, rsaSigner)
# print rs
