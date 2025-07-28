from PIL import Image
import base64
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

def pad(data):
    pad_len = 16 - len(data) % 16
    return data + (chr(pad_len) * pad_len).encode()

def unpad(data):
    pad_len = data[-1]
    return data[:-pad_len]

def encrypt_message(message, password):
    salt = get_random_bytes(16)
    key = PBKDF2(password, salt, dkLen=32, count=100000)
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(message.encode()))
    encrypted = salt + cipher.iv + ct_bytes
    return base64.b64encode(encrypted).decode()

def decrypt_message(encrypted_text, password):
    try:
        data = base64.b64decode(encrypted_text)
        salt = data[:16]
        iv = data[16:32]
        ct = data[32:]
        key = PBKDF2(password, salt, dkLen=32, count=100000)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(ct)).decode()
    except Exception:
        return "[!] Decryption failed. Incorrect password or corrupted data."

def text_to_binary(text):
    return ''.join(format(ord(c), '08b') for c in text)

def binary_to_text(binary):
    chars = [binary[i:i+8] for i in range(0, len(binary), 8)]
    return ''.join([chr(int(b, 2)) for b in chars])

def encode_image(image_path, message, bits=1):
    image = Image.open(image_path).convert('RGB')
    data = list(image.getdata())
    binary_msg = text_to_binary(message) + '1111111111111110'
    msg_index = 0
    new_pixels = []

    for pixel in data:
        r, g, b = pixel
        rgb = [r, g, b]
        new_rgb = []
        for color in rgb:
            if msg_index < len(binary_msg):
                bits_to_write = binary_msg[msg_index:msg_index + bits].ljust(bits, '0')
                new_bin = format(color, '08b')[:-bits] + bits_to_write
                new_rgb.append(int(new_bin, 2))
                msg_index += bits
            else:
                new_rgb.append(color)
        new_pixels.append(tuple(new_rgb))

    new_img = Image.new(image.mode, image.size)
    new_img.putdata(new_pixels)
    return new_img

def embed(image_path, message, bits=1, password=None, output_path="output.png"):
    if password:
        message = encrypt_message(message, password)
    encoded_img = encode_image(image_path, message, bits)
    encoded_img.save(output_path)
    return output_path

def extract(image_path, bits=1, password=None):
    image = Image.open(image_path).convert('RGB')
    data = list(image.getdata())
    binary_msg = ""
    for pixel in data:
        for color in pixel:
            binary_msg += format(color, '08b')[-bits:]
    delimiter = '1111111111111110'
    end_index = binary_msg.find(delimiter)
    if end_index == -1:
        return "[!] No message found."
    binary_msg = binary_msg[:end_index]
    message = binary_to_text(binary_msg)
    if password:
        return decrypt_message(message, password)
    return message
