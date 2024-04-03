import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
import os
import time


def print_progress_bar(iteration, total, prefix='', suffix='', decimals=1, length=50, fill='█'):

    percent = ("{0:." + str(decimals) + "f}").format(100 *
                                                     (iteration / float(total)))
    filled_length = int(length * iteration // total)
    bar = fill * filled_length + '-' * (length - filled_length)
    print(f'\r{prefix} |{bar}| {percent}% {suffix}', end="\r")
    if iteration == total:
        print()


def encrypt_with_public_key(message, public_key):
    rsa_cipher = PKCS1_OAEP.new(RSA.import_key(public_key))
    return rsa_cipher.encrypt(message)


client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((input("Enter the receiver IP: "), 8080))

public_key = client.recv(2048)
print("Public key received.")

aes_key = get_random_bytes(16)
iv = get_random_bytes(16)

encrypted_aes_key_iv = encrypt_with_public_key(aes_key + iv, public_key)
client.send(len(encrypted_aes_key_iv).to_bytes(4, 'big'))
client.send(encrypted_aes_key_iv)

file_path = input("Enter the file path: ")
file_name = os.path.basename(file_path)
with open(file_path, "rb") as file:
    data = file.read()

start_time = time.time()
cipher_aes = AES.new(aes_key, AES.MODE_EAX, iv)
encrypted_data = cipher_aes.encrypt(data)
end_time = time.time()
print(f"Encryption took {end_time - start_time} seconds.")

client.send(len(file_name).to_bytes(2, 'big'))
client.send(file_name.encode())
client.send(len(encrypted_data).to_bytes(4, 'big'))

chunk_size = 4096
total_size_sent = 0

print_progress_bar(total_size_sent, len(encrypted_data),
                   prefix='Progress:', suffix='Complete', length=50)

for i in range(0, len(encrypted_data), chunk_size):
    client.send(encrypted_data[i:i+chunk_size])
    total_size_sent += chunk_size
    print_progress_bar(min(total_size_sent, len(encrypted_data)), len(
        encrypted_data), prefix='Progress:', suffix='Complete', length=50)

print(f"\nFile '{file_name}' sent successfully.")
client.close()
