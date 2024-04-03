from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
import socket
import time


def print_progress_bar(iteration, total, prefix='', suffix='', decimals=1, length=50, fill='█'):

    percent = ("{0:." + str(decimals) + "f}").format(100 *
                                                     (iteration / float(total)))
    filled_length = int(length * iteration // total)
    bar = fill * filled_length + '-' * (length - filled_length)
    print(f'\r{prefix} |{bar}| {percent}% {suffix}', end="\r")
    if iteration == total:
        print()


def decrypt_with_private_key(encrypted_message, private_key):
    rsa_cipher = PKCS1_OAEP.new(RSA.import_key(private_key))
    return rsa_cipher.decrypt(encrypted_message)


def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key


private_key, public_key = generate_rsa_keys()

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(("0.0.0.0", 8080))
server.listen(1)
print("Listening for connections...")

client, addr = server.accept()
print(f"Connected by {addr}")

client.sendall(public_key)

encrypted_aes_key_size = client.recv(4)
encrypted_aes_key_size = int.from_bytes(encrypted_aes_key_size, 'big')

encrypted_aes_key_iv = client.recv(encrypted_aes_key_size)
decrypted_aes_key_iv = decrypt_with_private_key(
    encrypted_aes_key_iv, private_key)

aes_key = decrypted_aes_key_iv[:16]
iv = decrypted_aes_key_iv[16:]

file_name_length = client.recv(2)
file_name_length = int.from_bytes(file_name_length, 'big')
file_name = client.recv(file_name_length).decode()

encrypted_data_size = client.recv(4)
encrypted_data_size = int.from_bytes(encrypted_data_size, 'big')

received_data = bytearray()
total_size_received = 0
print_progress_bar(total_size_received, encrypted_data_size,
                   prefix='Progress:', suffix='Complete', length=50)

start_time = time.time()
while len(received_data) < encrypted_data_size:
    chunk = client.recv(4096)
    if not chunk:
        break
    received_data.extend(chunk)
    total_size_received += len(chunk)
    print_progress_bar(total_size_received, encrypted_data_size,
                       prefix='Progress:', suffix='Complete', length=50)


data = AES.new(aes_key, AES.MODE_EAX, iv).decrypt(received_data)

with open(file_name, "wb") as file:
    file.write(data)
end_time = time.time()
print(f"File '{file_name}' has been received and decrypted.")
print(f"Time taken: {end_time - start_time:.2f} seconds.")
client.close()
server.close()
