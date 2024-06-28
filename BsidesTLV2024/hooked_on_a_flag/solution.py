from Crypto.Cipher import AES
from hashlib import sha256
import base64

key = b'8[V3@eL521#@R2XNX3?4vygXw4$2Jr'
key = sha256(key).digest()

iv = b'Fh@S/xW]y$?q'

ciphertext = base64.b64decode(b'l5wMg7HQCuXMk3Dkf3GDlLX52+VM0bZcDCQIZjyVJlKZ3hh9LMIUY13zzlgimU3IAAAAAAAAAAAAAAAAAAAAAA==')

aes = AES.new(key, AES.MODE_GCM, iv)
print(aes.decrypt(ciphertext))
