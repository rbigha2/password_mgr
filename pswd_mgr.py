import os
import json
from getpass import getpass
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from base64 import b64encode, b64decode

def encrypt(password, plaintext):
	backend = default_backend()
	salt = os.urandom(16)
	kdf = PBKDF2HMAC(
		algorithm=hashes.SHA256(),
		length=32,
		salt=salt,
		iterations=100000,
		backend=backend
)
	key = kdf.derive(password.encode())
	iv = os.urandom(16)
	cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
	encryptor = cipher.encryptor()
	ciphertext = encryptor.update(plaintext.encode('utf-8')) + encryptor.finalize()
	return b64encode(salt + iv + ciphertext).decode('utf-8')

def decrypt(password, ciphertext):
	backend = default_backend()
	decoded_data = b64decode(ciphertext.encode('utf-8'))
	salt = decoded_data[:16]
	iv = decoded_data[16:32]
	ciphertext = decoded_data[32:]
	kdf = PBKDF2HMAC(
		algorithm=hashes.SHA256(),
		length=32,
		salt=salt,
		iterations=100000,
		backend=backend
	)
	key = kdf.derive(password.encode())
	cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
	decryptor = cipher.decryptor()
	plaintext =decryptor.update(ciphertext) + decryptor.finalize()
	return plaintext.decode('utf-8')

def main():
	print("Welcome to Bigham's Password Manager")
	master_password = getpass("Enter your Bigham password: ")
	data = {}
	try:
		with open("password.json", "r") as f:
			encrypted_data = f.read()
		data = json.loads(decrypt(master_password, encrypted_data))
	except (FileNotFoundError, ValueError, KeyError):
	  print("No data found or invalid Bigham password. Starting with an empty password list")

	while True:
		action = input("Choose an action (add, get, quit): ")
		if action.lower() == "add":
	  		site = input("Enter the site name: ")
	  		username = input("Enter the username: ")
	  		password = getpass("Enter the password: ")
	  		data[site] = {"username": username, "password": password}

		elif action.lower() == "get":
			site = input("Enter the site name: ")
			if site in data:
				print(f"Username: {data[site]['username']}")
				print(f"Password: {data[site]['password']}")
		else:
			print("No data found for this site.")

		elif action.lower() == "quit":
			encrypted_data = encrypt(master_password, json.dumps(data))
			with open("passwords.json", "w") as f:
				f.write(encrypted_data)
			print("Data saved. Bye-bye!")
			break
		else:
			print("Invalid action. Please enter 'add', 'get' or 'quit'.")

if __name__ == "__main__":
	main()