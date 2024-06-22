from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import MD5
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64

# Generate RSA keys (for demonstration, both sender and receiver keys will be generated here)
receiver_key = RSA.generate(2048)
receiver_public_key = receiver_key.publickey()

# Sender's operations
def sender_operations(message, pub_key):
    m = message.encode('utf-8')
    x = get_random_bytes(16)
    rsa_cipher = PKCS1_OAEP.new(pub_key)
    y = rsa_cipher.encrypt(x)
    hash_md5 = MD5.new()
    hash_md5.update(x)
    k = hash_md5.digest()
    aes_cipher = AES.new(k, AES.MODE_CBC)
    c = aes_cipher.encrypt(pad(m, AES.block_size))
    c_with_iv = aes_cipher.iv + c
    return base64.b64encode(y), base64.b64encode(c_with_iv)

# Receiver's operations
def receiver_operations(encoded_y, encoded_c_with_iv, priv_key):
    y = base64.b64decode(encoded_y)
    c_with_iv = base64.b64decode(encoded_c_with_iv)
    rsa_cipher = PKCS1_OAEP.new(priv_key)
    x = rsa_cipher.decrypt(y)
    hash_md5 = MD5.new()
    hash_md5.update(x)
    k = hash_md5.digest()
    iv = c_with_iv[:AES.block_size]
    c = c_with_iv[AES.block_size:]
    aes_cipher = AES.new(k, AES.MODE_CBC, iv)
    m = unpad(aes_cipher.decrypt(c), AES.block_size).decode('utf-8')
    return m

# Example usage
plaintext_message = "Hello, World!"
y, c_with_iv = sender_operations(plaintext_message, receiver_public_key)
decrypted_message = receiver_operations(y, c_with_iv, receiver_key)

# Output
print(f"Original message: {plaintext_message}")
print(f"Decrypted message: {decrypted_message}")