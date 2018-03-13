#!/usr/bin/env python3

import os.path
import time
import getpass
import argparse
import base64
import hashlib
from Crypto import Random
from Crypto.Cipher import AES

ENCODING = 'utf-8'

parser = argparse.ArgumentParser(description='Encrypt/decrypt any file with a passphrase.')
parser.add_argument('files', metavar='Files', nargs='+', help='files to be encrypted/decrypted')
parser.add_argument('-k', '--key', default=None, nargs='?', help='key to encrypt/decrypt', action="store")

group = parser.add_mutually_exclusive_group(required=True)
group.add_argument('-e', '--encrypt', action='store_true')
group.add_argument('-d', '--decrypt', action='store_true')

def encrypt_file(file, key=None):
    if os.path.isdir(file):
        for path, dirs, files in os.walk(file):
            for filename in files:
                fullpath = os.path.join(path, filename)
                if os.path.isfile(fullpath):
                    encrypt_file(fullpath, key)
        return
    elif not os.path.isfile(file):
        print('%s not found' % file)
        return
    
    print('Encrypt %s' % file)

    getkey = None
    if not key:
        while True:
            try:
                getkey = getpass.getpass('Enter encryption key')
                confirm = getpass.getpass('Confirm encryption key')

                if getkey and getkey == confirm:
                    break
            except (KeyboardInterrupt, EOFError):
                exit(0)

    with open(file, 'r+') as f:
        data = f.read()
        encr = encrypt_data(key or getkey, data)
        f.seek(0)
        f.write(encr)
        f.truncate()

def decrypt_file(file, key=None):
    if os.path.isdir(file):
        for path, dirs, files in os.walk(file):
            for filename in files:
                fullpath = os.path.join(path, filename)
                if os.path.isfile(fullpath):
                    decrypt_file(fullpath, key)
        return
    elif not os.path.isfile(file):
        print('%s not found' % file)
        return

    print('Decrypt %s' % file)

    while True:
        try:
            if not key:
                getkey = getpass.getpass('Enter encryption key')

            with open(file, 'r+') as f:
                data = f.read()
                decr = decrypt_data(key or getkey, data)

                if decr:
                    f.seek(0)
                    f.write(decr)
                    f.truncate()
                    break
                
                raise ValueError('Wrong key')
        except (KeyboardInterrupt, EOFError):
            exit(0)
        except ValueError:
            print('Wrong encryption key\n')
            if key:
                break

def encrypt_data(key, text):
    key = hashlib.sha256(key.encode()).digest()
    data = add_padding(text)
    
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)

    encr_text = cipher.encrypt(data)
    return base64.b64encode(iv + encr_text).decode(ENCODING)

def decrypt_data(key, text):
    key = hashlib.sha256(key.encode()).digest()
    data = base64.b64decode(text)
    
    iv = data[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    decr_text = cipher.decrypt(data[AES.block_size:])
    return remove_padding(decr_text).decode(ENCODING)

def add_padding(s):
    pad_size = AES.block_size - len(s) % AES.block_size
    return s + pad_size * chr(pad_size)

def remove_padding(s):
    return s[:-ord(s[len(s) - 1:])]

if __name__ == '__main__':
    args = parser.parse_args()

    if args.encrypt:
        for f in args.files:
            encrypt_file(f, args.key)
    elif args.decrypt:
        for f in args.files:
            decrypt_file(f, args.key)
