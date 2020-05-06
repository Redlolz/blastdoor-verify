from base64 import b64encode, b64decode
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from riposte import Riposte
from riposte.printer import Palette
import os.path
import sys

blast = Riposte('[blastdoor]$ ')

@blast.command('help')
def help():
    blast.status("List of commands")
    blast.status("generate <filename>       - Generate a private RSA key")
    blast.status("publickey <filename>      - Generate public key from private key")
    blast.status("sign <filename> <message> - Sign message with private key")
    blast.status("exit                      - Exit the program")

@blast.command('generate')
def generate(filename: str):
    if not os.path.isfile(filename):
        # Generate RSA keypair
        blast.status("Generating RSA key...")
        key = RSA.generate(4096)
        enc_key = key.export_key()

        blast.status("Writing private key file...")
        public_key_file = open(filename, 'wb')
        public_key_file.write(enc_key)
        blast.success("Done")
    else:
        blast.error("File already exists!")

@blast.command('publickey')
def publickey(filename: str):
    if os.path.isfile(filename):
        key = RSA.import_key(open(filename).read())
        blast.print(Palette.CYAN.format(key.publickey().export_key().decode('utf-8')))
    else:
        blast.error("File doesn't exist!")

@blast.command('sign')
def sign(filename: str, message: str):
    if os.path.isfile(filename):
        key = RSA.import_key(open(filename).read())
        h = SHA256.new(message.encode('utf-8'))
        signature = pkcs1_15.new(key).sign(h)
        blast.print(Palette.CYAN.format(b64encode(signature).decode('utf-8')))
    else:
        blast.error("File doesn't exists!")

@blast.command('exit')
def exit():
    blast.status("Goobye!")
    sys.exit()

blast.run()