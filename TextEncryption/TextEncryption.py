from flask import Flask, request, jsonify, render_template
from Crypto.Cipher import AES, DES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64

app = Flask(__name__)

def pad(text, block_size):
    return text + (block_size - len(text) % block_size) * chr(block_size - len(text) % block_size)

def unpad(text):
    return text[:-ord(text[len(text)-1:])]

# AES Encryption and Decryption
def aes_encrypt(text, key):
    cipher = AES.new(key.encode('utf-8'), AES.MODE_ECB)
    padded_text = pad(text, AES.block_size)
    encrypted = cipher.encrypt(padded_text.encode('utf-8'))
    return base64.b64encode(encrypted).decode('utf-8')

def aes_decrypt(encrypted_text, key):
    cipher = AES.new(key.encode('utf-8'), AES.MODE_ECB)
    decrypted = cipher.decrypt(base64.b64decode(encrypted_text))
    return unpad(decrypted.decode('utf-8'))

# DES Encryption and Decryption
def des_encrypt(text, key):
    cipher = DES.new(key.encode('utf-8'), DES.MODE_ECB)
    padded_text = pad(text, DES.block_size)
    encrypted = cipher.encrypt(padded_text.encode('utf-8'))
    return base64.b64encode(encrypted).decode('utf-8')

def des_decrypt(encrypted_text, key):
    cipher = DES.new(key.encode('utf-8'), DES.MODE_ECB)
    decrypted = cipher.decrypt(base64.b64decode(encrypted_text))
    return unpad(decrypted.decode('utf-8'))

# RSA Encryption and Decryption
def rsa_generate_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def rsa_encrypt(text, public_key):
    rsa_key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    encrypted = cipher.encrypt(text.encode('utf-8'))
    return base64.b64encode(encrypted).decode('utf-8')

def rsa_decrypt(encrypted_text, private_key):
    rsa_key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    decrypted = cipher.decrypt(base64.b64decode(encrypted_text))
    return decrypted.decode('utf-8')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt():
    data = request.json
    text = data['text']
    algorithm = data['algorithm']
    key = data.get('key', None)
    
    if algorithm == 'AES':
        if len(key) != 16:
            return jsonify({'error': 'AES key must be 16 characters long'}), 400
        result = aes_encrypt(text, key)
    elif algorithm == 'DES':
        if len(key) != 8:
            return jsonify({'error': 'DES key must be 8 characters long'}), 400
        result = des_encrypt(text, key)
    elif algorithm == 'RSA':
        public_key = key.encode('utf-8')
        result = rsa_encrypt(text, public_key)
    else:
        return jsonify({'error': 'Unsupported algorithm'}), 400
    
    return jsonify({'encrypted': result})

@app.route('/decrypt', methods=['POST'])
def decrypt():
    data = request.json
    encrypted_text = data['encrypted']
    algorithm = data['algorithm']
    key = data.get('key', None)

    if algorithm == 'AES':
        if len(key) != 16:
            return jsonify({'error': 'AES key must be 16 characters long'}), 400
        result = aes_decrypt(encrypted_text, key)
    elif algorithm == 'DES':
        if len(key) != 8:
            return jsonify({'error': 'DES key must be 8 characters long'}), 400
        result = des_decrypt(encrypted_text, key)
    elif algorithm == 'RSA':
        private_key = key.encode('utf-8')
        result = rsa_decrypt(encrypted_text, private_key)
    else:
        return jsonify({'error': 'Unsupported algorithm'}), 400
    
    return jsonify({'decrypted': result})

if __name__ == '__main__':
    app.run(debug=True,port=8000)