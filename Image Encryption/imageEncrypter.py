from flask import Flask, request, jsonify, send_file, render_template
from Crypto.Cipher import AES
import os

app = Flask(__name__)


KEY = b'1234567890123456'  # 16-byte AES key

BASE_DIR = r'E:\\Internships\\PinnacleLabs_Cybersecurity\\Image Encryption'
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
ENCRYPTED_FOLDER = os.path.join(BASE_DIR, 'encrypted')
DECRYPTED_FOLDER = os.path.join(BASE_DIR, 'decrypted')


os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(ENCRYPTED_FOLDER, exist_ok=True)
os.makedirs(DECRYPTED_FOLDER, exist_ok=True)

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def pad(data):
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len] * pad_len)

def unpad(data):
    pad_len = data[-1]
    return data[:-pad_len]

# Image Encryption
def encrypt_image(file_path):
    try:
        with open(file_path, 'rb') as f:
            image_data = f.read()

        cipher = AES.new(KEY, AES.MODE_ECB)
        encrypted_data = cipher.encrypt(pad(image_data))

        encrypted_path = os.path.join(ENCRYPTED_FOLDER, os.path.basename(file_path))
        with open(encrypted_path, 'wb') as f:
            f.write(encrypted_data)

        return encrypted_path
    except Exception as e:
        print(f"Encryption failed: {e}")
        return None

# Image Decryption
def decrypt_image(file_path):
    try:
        with open(file_path, 'rb') as f:
            encrypted_data = f.read()

        cipher = AES.new(KEY, AES.MODE_ECB)
        decrypted_data = unpad(cipher.decrypt(encrypted_data))

        decrypted_path = os.path.join(DECRYPTED_FOLDER, os.path.basename(file_path))
        with open(decrypted_path, 'wb') as f:
            f.write(decrypted_data)

        return decrypted_path
    except Exception as e:
        print(f"Decryption failed: {e}")
        return None

@app.route('/')
def index():
    return render_template('image_encryption.html')

@app.route('/encrypt', methods=['POST'])
def encrypt():
    if 'image' not in request.files:
        return jsonify({"error": "No file uploaded."}), 400

    image = request.files['image']

    if not allowed_file(image.filename):
        return jsonify({"error": "Unsupported file format."}), 400

    file_path = os.path.join(UPLOAD_FOLDER, image.filename)
    image.save(file_path)

    encrypted_path = encrypt_image(file_path)
    if encrypted_path:
        return send_file(encrypted_path, as_attachment=True)
    else:
        return jsonify({"error": "Failed to encrypt the image."}), 500

@app.route('/decrypt', methods=['POST'])
def decrypt():
    if 'image' not in request.files:
        return jsonify({"error": "No file uploaded."}), 400

    image = request.files['image']

    if not allowed_file(image.filename):
        return jsonify({"error": "Unsupported file format."}), 400

    file_path = os.path.join(UPLOAD_FOLDER, image.filename)
    image.save(file_path)

    decrypted_path = decrypt_image(file_path)
    if decrypted_path:
        return send_file(decrypted_path, as_attachment=True)
    else:
        return jsonify({"error": "Failed to decrypt the image."}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)
