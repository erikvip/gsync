GSync Transparent Encryption Notes
==================================

gsync changes:
libgsync/options/doc.py
+     --ignore-size           ignore size and use modtime only. Must be used for transparent encryption.



libgsync/sync/__init__.py
+            # Must be disabled for encryption check
+            if srcFile.fileSize != dstFile.fileSize and GsyncOptions.options['--ignore-size'] != 1:


/libgsync/sync/file/local/__init__.py

+from libgsync.crypt import *
+import tempfile


+        #Encryption would happen here...
+        t = TransparentCrypt()
+        temp = tempfile.NamedTemporaryFile()
+        plain_file = path
+        path = temp.name
+        t.encrypt_file(plain_file, path, "asdf")




crypt/__init__.py
# Transparent Encryption routines

from hashlib import md5
from Crypto.Cipher import AES
from Crypto import Random

class TransparentCrypt(object):
        def derive_key_and_iv(self, password, salt, key_length, iv_length):
            d = d_i = ''
            while len(d) < key_length + iv_length:
                d_i = md5(d_i + password + salt).digest()
                d += d_i
            return d[:key_length], d[key_length:key_length+iv_length]

        def encrypt(self, in_file, out_file, password, key_length=32):
            bs = AES.block_size
            salt = Random.new().read(bs - len('Salted__'))
            key, iv = self.derive_key_and_iv(password, salt, key_length, bs)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            out_file.write('Salted__' + salt)
            finished = False
            while not finished:
                chunk = in_file.read(1024 * bs)
                if len(chunk) == 0 or len(chunk) % bs != 0:
                    padding_length = bs - (len(chunk) % bs)
                    chunk += padding_length * chr(padding_length)
                    finished = True
                out_file.write(cipher.encrypt(chunk))

        def decrypt(self, in_file, out_file, password, key_length=32):
            bs = AES.block_size
            salt = in_file.read(bs)[len('Salted__'):]
            key, iv = derive_key_and_iv(password, salt, key_length, bs)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            next_chunk = ''
            finished = False
            while not finished:
                chunk, next_chunk = next_chunk, cipher.decrypt(in_file.read(1024 * bs))
                if len(next_chunk) == 0:
                    padding_length = ord(chunk[-1])
                    if padding_length < 1 or padding_length > bs:
                       raise ValueError("bad decrypt pad (%d)" % padding_length)
                    # all the pad-bytes must be the same
                    if chunk[-padding_length:] != (padding_length * chr(padding_length)):
                       # this is similar to the bad decrypt:evp_enc.c from openssl program
                       raise ValueError("bad decrypt")
                    chunk = chunk[:-padding_length]
                    finished = True
                out_file.write(chunk)

        def encrypt_file(self, file_name, output, key):
            with open(file_name, 'rb') as in_file:
                with open(output, 'wb') as out_file:
                        self.encrypt(in_file, out_file, key)
            return file_name + ".enc"

        def decrypt_file(self, file_name, output, key):
            with open(file_name, 'rb') as in_file:
                with open(output, 'wb') as out_file:
                        self.decrypt(in_file, out_file, key)







