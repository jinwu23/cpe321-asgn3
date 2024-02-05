import sys
from Crypto.Util import number
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import random
import hashlib

RELATIVE_PRIME = 65537
PRIME_LENGTH = 2048

def main():
    if len(sys.argv) != 2:
        print("Usage Error: rsa.py [1,2]")
    # Encrypt and Decrypt message using RSA
    if sys.argv[1] == "1":
        # Generate public and private key
        prime_1 = number.getPrime(PRIME_LENGTH)
        prime_2 = number.getPrime(PRIME_LENGTH)
        # ensure that both primes are not the same
        while prime_1 == prime_2:
            prime_2 = number.getPrime(PRIME_LENGTH)
        prime_product = prime_1 * prime_2
        euler_totient = (prime_1 - 1) * (prime_2 - 1)
        d = pow(RELATIVE_PRIME, -1, euler_totient)
        public_key = (RELATIVE_PRIME, prime_product)
        private_key = (d, prime_product)

        # Encrypt Integer
        selected_string = "Hello!"
        selected_int = int(selected_string.encode().hex(), 16)
        encrypted_int = pow(selected_int, public_key[0], public_key[1])

        print(f"Selected String: {selected_string}")
        print(f"Selected Int: {selected_int}")
        print(f"Encrypted Int: {encrypted_int}")

        decrypted_int = pow(encrypted_int, private_key[0], public_key[1])
        decrypted_string = bytes.fromhex(hex(decrypted_int)[2:]).decode()

        print(f"Decrypted Int: {decrypted_int}")
        print(f"Decrypted String: {decrypted_string}")

    # Mallory attack on RSA
    elif sys.argv[1] == "2":
        # Generate public and private key
        prime_1 = number.getPrime(PRIME_LENGTH)
        prime_2 = number.getPrime(PRIME_LENGTH)
        # ensure that both primes are not the same
        while prime_1 == prime_2:
            prime_2 = number.getPrime(PRIME_LENGTH)
        # generate keys
        prime_product = prime_1 * prime_2
        euler_totient = (prime_1 - 1) * (prime_2 - 1)
        d = pow(RELATIVE_PRIME, -1, euler_totient)
        alice_public_key = (RELATIVE_PRIME, prime_product)
        alice_private_key = (d, prime_product)
        # Bob computes ciphertext to share with alice
        bob_plaintext = random.randint(0, alice_public_key[1])
        bob_ciphertext = pow(bob_plaintext, alice_public_key[0], alice_public_key[1])
        
        # Mallory intercepts ciphertext and changes it to 1
        mallory_changed_ciphertext = 1

        # Alice generates secret key off of bobs ciphertext
        alice_message = "Hi Bob!"
        alice_secret_key = pow(mallory_changed_ciphertext, alice_private_key[0], alice_public_key[1])
        alice_secret_key_bytes = str(alice_secret_key).encode('utf-8')
        alice_secret_key = hashlib.sha256(alice_secret_key_bytes).hexdigest()[:16]
        print(f"Alice secret key: {alice_secret_key}")
        cipher = AES.new(alice_secret_key.encode('utf-8'), AES.MODE_CBC)
        alice_message_ciphertext = cipher.encrypt(pad(alice_message.encode('utf-8'), AES.block_size))
        iv = cipher.iv

        # Mallory intercepts Alices ciphertext and deciphers 
        mallory_key_bytes = str(1).encode('utf-8')
        mallory_secret_key = hashlib.sha256(mallory_key_bytes).hexdigest()[:16]
        print(f"Mallory secret key: {mallory_secret_key}")
        mallory_cipher = AES.new(mallory_secret_key.encode('utf-8'), AES.MODE_CBC, iv)
        alice_message_plaintext = unpad(mallory_cipher.decrypt(alice_message_ciphertext), AES.block_size).decode()
        print(f"Mallory decoded Alice plaintext: {alice_message_plaintext}")

    # Show how Mallory can create a valid signature given 2 messages
    elif sys.argv[1] == "3":
        # Generate public and private key
        prime_1 = number.getPrime(PRIME_LENGTH)
        prime_2 = number.getPrime(PRIME_LENGTH)
        # ensure that both primes are not the same
        while prime_1 == prime_2:
            prime_2 = number.getPrime(PRIME_LENGTH)
        # generate keys
        prime_product = prime_1 * prime_2
        euler_totient = (prime_1 - 1) * (prime_2 - 1)
        d = pow(RELATIVE_PRIME, -1, euler_totient)
        alice_public_key = (RELATIVE_PRIME, prime_product)
        alice_private_key = (d, prime_product)
        # sign messages
        message_1 = "Hello"
        message_1 = int(message_1.encode().hex(), 16)
        message_2 = "Bob"
        message_2 = int(message_2.encode().hex(), 16)
        signature_1 = pow(message_1, alice_private_key[0], alice_private_key[1])
        signature_2 = pow(message_2, alice_private_key[0], alice_private_key[1])
        # Verify message signatures
        if pow(signature_1, alice_public_key[0], alice_public_key[1]) == message_1:
            message_1_string = bytes.fromhex(hex(message_1)[2:]).decode()
            print(f"Message 1 is verified, message: {message_1_string}")
        if pow(signature_2, alice_public_key[0], alice_public_key[1]) == message_2:
            message_2_string = bytes.fromhex(hex(message_2)[2:]).decode()
            print(f"Message 2 is verified, message: {message_2_string}")
        # Mallory calculates message and signature from alices     
        mallory_message = message_1 * message_2
        mallory_signature = signature_1 * signature_2 % alice_public_key[1]
        print(f"Mallory calculated signature: {mallory_signature}")
        if pow(mallory_signature, alice_public_key[0], alice_public_key[1]) == mallory_message:
            print(f"Mallory Message is verified, message: {mallory_message}")
    return

if __name__ == "__main__":
    main()