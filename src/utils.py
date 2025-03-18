from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.Cipher import PKCS1_OAEP
from argparse import ArgumentParser

def hashFile(file: bytes):
  hash = SHA256.new()
  hash.update(file)
  return hash.digest()



def generateRSAKey(keySize=2048):
  privateKey = RSA.generate(keySize)
  publicKey = privateKey.publickey()
  return privateKey, publicKey


def savePrivateKey(privateKey: RSA.RsaKey, fileName=None):
  if fileName is None:
    return privateKey.export_key()
  else:
    with open(fileName, 'wb') as f:
      f.write(privateKey.export_key())
    return None


def savePublicKey(publicKey: RSA.RsaKey, fileName=None):
  if fileName is None:
    return publicKey.export_key()
  else:
    with open(fileName, 'wb') as f:
      f.write(publicKey.export_key())
    return None


def generateRSAKeys(publicKeyFile: str, privateKeyFile: str, keySize=2048):
  privateKey, publicKey = generateRSAKey(keySize)
  savePublicKey(publicKey, publicKeyFile)
  savePrivateKey(privateKey, privateKeyFile)


def encryptRSA(message: bytes, publicKey: RSA.RsaKey):
  cipher_rsa = PKCS1_OAEP.new(publicKey)
  encrypted_message = cipher_rsa.encrypt(message)
  return encrypted_message


def decryptRSA(encrypted_message: bytes, privateKey: RSA.RsaKey):
  cipher_rsa = PKCS1_OAEP.new(privateKey)
  decrypted_message = cipher_rsa.decrypt(encrypted_message)
  return decrypted_message



def encryptAES(message: bytes, key: bytes):
  cipher_aes = AES.new(key, AES.MODE_CBC)
  encrypted_message = cipher_aes.encrypt(pad(message, AES.block_size))
  return bytes(cipher_aes.iv) + encrypted_message


def decryptAES(encryptedMessage: bytes, key: bytes):
  iv = encryptedMessage[:AES.block_size]
  cipherBytes = encryptedMessage[AES.block_size:]
  cipherAES = AES.new(key, AES.MODE_CBC, iv)
  decrypted_message = unpad(cipherAES.decrypt(cipherBytes), AES.block_size)
  return decrypted_message


def loadEncryptedAESKey(encryptedKeyOrFileName, privateKey: RSA.RsaKey):
  if type(encryptedKeyOrFileName).isinstance(str):
    with open(encryptedKeyOrFileName, "rb") as f:
      encryptedKey = f.read()
  else:
    encryptedKey = encryptedKeyOrFileName

  cipher_rsa = PKCS1_OAEP.new(privateKey)
  decrypted_key = cipher_rsa.decrypt(encryptedKey)
  return AES.new(decrypted_key, AES.MODE_CBC)


def saveEncryptAESKey(key: bytes, publicKey: RSA.RsaKey, fileName=None):
  cipher_rsa = PKCS1_OAEP.new(publicKey)
  encrypted_key = cipher_rsa.encrypt(key)
  if fileName is None:
    return encrypted_key
  else:
    with open(fileName, 'wb') as f:
      f.write(encrypted_key)
    return None



def hybridEncrypt(receiverPublicKeyFile: str, inputFile: str, outputFile: str, outputEncryptedSymmKeyFile: str):
  with open(receiverPublicKeyFile, 'rb') as f:
    receiverPublicKey = RSA.import_key(f.read())

  with open(inputFile, 'rb') as f:
    input_message = f.read()

  hashValue = hashFile(input_message)

  symKey = get_random_bytes(AES.block_size)
  encrypted_message = encryptAES(input_message, symKey)
  encrypted_symKey = encryptRSA(symKey, receiverPublicKey)
  
  with open(outputFile, 'wb') as f:
    f.write(hashValue + encrypted_message)
  with open(outputEncryptedSymmKeyFile, 'wb') as f:
    f.write(encrypted_symKey)


def hybridDecrypt(senderPrivateKeyFile: str, inputEncryptedFile: str, outputFile: str, inputEncryptedSymKeyFile: str, checkHashSHA256=True):
  with open(senderPrivateKeyFile, 'rb') as f:
    senderPrivateKey = RSA.import_key(f.read())

  with open(inputEncryptedFile, 'rb') as f:
    encrypted_message = f.read()

  with open(inputEncryptedSymKeyFile, 'rb') as f:
    encrypted_symKey = f.read()

  hashValue = encrypted_message[:SHA256.digest_size]
  encrypted_message = encrypted_message[SHA256.digest_size:]

  symKey = decryptRSA(encrypted_symKey, senderPrivateKey)
  decrypted_message = decryptAES(encrypted_message, symKey)
  
  with open(outputFile, 'wb') as f:
    f.write(decrypted_message)

  if checkHashSHA256:
    if hashFile(decrypted_message) != hashValue:
      return False
    else:
      return True
  else:
    return None


if __name__ == "__main__":
  parser = ArgumentParser(description="Generate public and private keys for RSA encryption and decryption (in PEM format).")
  parser.add_argument("--public_key", help="Public key file name or path", default="public_key.pub")
  parser.add_argument("--private_key", help="Private key file name or path", default="private_key.key")
  parser.add_argument("--key_size", help="Key size in bits", default=2048, type=int)

  args = parser.parse_args()
  generateRSAKeys(args.public_key, args.private_key, int(args.key_size))