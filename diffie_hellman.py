import random
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from base64 import b64encode
import sys

PUBLIC_PRIME = int("B10B8F96", 16)
PUBLIC_PRIMITIVE_ROOT = int("A4D1CBD5", 16)

def main():
    if len(sys.argv) != 2:
        print("Usage Error: python diffie_hellman.py [1, 2a, 2b]")
        return
    
    if sys.argv[1] == "1":
        q = PUBLIC_PRIME
        a = PUBLIC_PRIMITIVE_ROOT

        # Compute Alice private (X_a) and public (Y_a)
        X_a = random.randint(0, PUBLIC_PRIME)
        Y_a = pow(a, X_a, q)
        print(f"Alice Private: {X_a}")
        print(f"Alice Public: {Y_a}")

        # Compute Bob private (X_b) and public (Y_b)
        X_b = random.randint(0, PUBLIC_PRIME)
        Y_b = pow(a, X_b, q)
        print(f"Bob Private: {X_b}")
        print(f"Bob Public: {Y_b}")

        # Calculate secret
        alice_secret = pow(Y_b, X_a, q)
        bob_secret = pow(Y_a, X_b, q)
        
        # Make sure secret is same 
        if alice_secret != bob_secret:
            print("Calculated secret is different for Alice and Bob")
            return

        # Calculate secret key using SHA256 and truncate to 16 bytes
        alice_secret_bytes = str(alice_secret).encode('utf-8')
        bob_secret_bytes = str(bob_secret).encode('utf-8')

        secret_key = hashlib.sha256(alice_secret_bytes).hexdigest()[:16]
        secret_key_2 = hashlib.sha256(bob_secret_bytes).hexdigest()[:16]
    
        # Check equality
        if secret_key != secret_key_2:
            print("SHA256 hashed secret key is different for ALice and Bob")
            return
        
        secret_key = secret_key[:16]
        secret_key_2 = secret_key_2[:16]

        print(f"Shared Secret Key: {secret_key}")

        # Encrypt messages using AES-CBC and secret_key
        alice_message = "Hi Bob!"
        bob_message = "Hi Alice!"

        cipher = AES.new(secret_key.encode('utf-8'), AES.MODE_CBC)

        alice_message_ciphertext = cipher.encrypt(pad(alice_message.encode('utf-8'), AES.block_size))
        bob_message_ciphertext = cipher.encrypt(pad(bob_message.encode('utf-8'), AES.block_size))
        iv = cipher.iv

        print(f"Alice Message Ciphertext: {alice_message_ciphertext}")
        print(f"Bob Message Ciphertext: {bob_message_ciphertext}")

        # Decrypt messages using AES-CBC and secret_key
        cipher = AES.new(secret_key.encode('utf-8'), AES.MODE_CBC, iv)
        alice_message_decoded = unpad(cipher.decrypt(alice_message_ciphertext), AES.block_size).decode()
        bob_message_decoded = unpad(cipher.decrypt(bob_message_ciphertext), AES.block_size).decode()
        
        print(f"Alice Message Decoded: {alice_message_decoded}")
        print(f"Bob Message Decoded: {bob_message_decoded}")

    elif sys.argv[1] == "2a":
        q = PUBLIC_PRIME
        a = PUBLIC_PRIMITIVE_ROOT
        # Compute Alice private (X_a) and public (Y_a)
        X_a = random.randint(0, PUBLIC_PRIME)
        Y_a = pow(a, X_a, q)
        # print(f"Alice Private: {X_a}")
        # print(f"Alice Public: {Y_a}")

        # Compute Bob private (X_b) and public (Y_b)
        X_b = random.randint(0, PUBLIC_PRIME)
        Y_b = pow(a, X_b, q)
        # print(f"Bob Private: {X_b}")
        # print(f"Bob Public: {Y_b}")

        # Alice sends public key to Bob but mallory changes it
        mallory_X_a = random.randint(0, PUBLIC_PRIME)
        mallory_Y_a = pow(a, mallory_X_a, q)
        mallory_X_b = random.randint(0, PUBLIC_PRIME)
        mallory_Y_b = pow(a, mallory_X_b, q)
        # print(f"Mallory Public A: {mallory_Y_a}")
        # print(f"Mallory Public B: {mallory_Y_b}")

        # Alice and Bob generates secret
        alice_secret = pow(mallory_Y_a, X_a, q)
        bob_secret = pow(mallory_Y_b, X_b, q) 
        mallory_alice_secret = pow(Y_a, mallory_X_a, q)
        mallory_bob_secret = pow(Y_b, mallory_X_b, q) 
        print(f"Alice calculated secret: {alice_secret}")
        print(f"Mallory-Alice calculated secret: {mallory_alice_secret}")
        print(f"Bob calculated secret: {bob_secret}")
        print(f"Mallory-Bob calculated secret: {mallory_bob_secret}")

        # Calculate secret key using SHA256 and truncate to 16 bytes
        alice_secret_bytes = str(alice_secret).encode('utf-8')
        bob_secret_bytes = str(bob_secret).encode('utf-8')
        alice_secret_key = hashlib.sha256(alice_secret_bytes).hexdigest()[:16]
        bob_secret_key = hashlib.sha256(bob_secret_bytes).hexdigest()[:16]
        print(f"Alice hashed secret key: {alice_secret_key}")
        print(f"Bob hashed secret key: {bob_secret_key}")

        # Alice and Bob sends each other a message 
        alice_message = "Hi Bob!"
        bob_message = "Hi Alice!"
        iv = get_random_bytes(AES.block_size)
        alice_cipher = AES.new(alice_secret_key.encode('utf-8'), AES.MODE_CBC, iv)
        bob_cipher = AES.new(bob_secret_key.encode('utf-8'), AES.MODE_CBC, iv)
        alice_message_ciphertext = alice_cipher.encrypt(pad(alice_message.encode('utf-8'), AES.block_size))
        bob_message_ciphertext = bob_cipher.encrypt(pad(bob_message.encode('utf-8'), AES.block_size))
        print(f"Alice Message Ciphertext: {alice_message_ciphertext}")
        print(f"Bob Message Ciphertext: {bob_message_ciphertext}")


        # Decrypt messages using AES-CBC and secret_key
        alice_cipher = AES.new(alice_secret_key.encode('utf-8'), AES.MODE_CBC, iv)
        bob_cipher = AES.new(bob_secret_key.encode('utf-8'), AES.MODE_CBC, iv)        
        bob_message_decoded = alice_cipher.decrypt(bob_message_ciphertext)
        alice_message_decoded = bob_cipher.decrypt(alice_message_ciphertext)
        
        print(f"Alice Message Decoded: {alice_message_decoded}")
        print(f"Bob Message Decoded: {bob_message_decoded}")

    elif sys.argv[1] == "2b":
        q = PUBLIC_PRIME
        a = 1 # mallory has changed a to 1

        # Compute Alice private (X_a) and public (Y_a)
        X_a = random.randint(0, PUBLIC_PRIME)
        Y_a = pow(a, X_a, q)
        # print(f"Alice Private: {X_a}")
        # print(f"Alice Public: {Y_a}")

        # Compute Bob private (X_b) and public (Y_b)
        X_b = random.randint(0, PUBLIC_PRIME)
        Y_b = pow(a, X_b, q)
        # print(f"Bob Private: {X_b}")
        # print(f"Bob Public: {Y_b}")

        # Alice sends public key to Bob but mallory changes it
        mallory_X_a = random.randint(0, PUBLIC_PRIME)
        mallory_Y_a = pow(a, mallory_X_a, q)
        mallory_X_b = random.randint(0, PUBLIC_PRIME)
        mallory_Y_b = pow(a, mallory_X_b, q)
        # print(f"Mallory Public A: {mallory_Y_a}")
        # print(f"Mallory Public B: {mallory_Y_b}")

        # Alice and Bob generates secret
        alice_secret = pow(mallory_Y_a, X_a, q)
        bob_secret = pow(mallory_Y_b, X_b, q) 
        mallory_alice_secret = pow(Y_a, mallory_X_a, q)
        mallory_bob_secret = pow(Y_b, mallory_X_b, q) 
        print(f"Alice calculated secret: {alice_secret}")
        print(f"Mallory-Alice calculated secret: {mallory_alice_secret}")
        print(f"Bob calculated secret: {bob_secret}")
        print(f"Mallory-Bob calculated secret: {mallory_bob_secret}")

        # Calculate secret key using SHA256 and truncate to 16 bytes
        alice_secret_bytes = str(alice_secret).encode('utf-8')
        bob_secret_bytes = str(bob_secret).encode('utf-8')
        alice_secret_key = hashlib.sha256(alice_secret_bytes).hexdigest()[:16]
        bob_secret_key = hashlib.sha256(bob_secret_bytes).hexdigest()[:16]
        print(f"Alice hashed secret key: {alice_secret_key}")
        print(f"Bob hashed secret key: {bob_secret_key}")

        # Alice and Bob sends each other a message 
        alice_message = "Hi Bob!"
        bob_message = "Hi Alice!"
        iv = get_random_bytes(AES.block_size)
        alice_cipher = AES.new(alice_secret_key.encode('utf-8'), AES.MODE_CBC, iv)
        bob_cipher = AES.new(bob_secret_key.encode('utf-8'), AES.MODE_CBC, iv)
        alice_message_ciphertext = alice_cipher.encrypt(pad(alice_message.encode('utf-8'), AES.block_size))
        bob_message_ciphertext = bob_cipher.encrypt(pad(bob_message.encode('utf-8'), AES.block_size))
        print(f"Alice Message Ciphertext: {alice_message_ciphertext}")
        print(f"Bob Message Ciphertext: {bob_message_ciphertext}")

        # Mallory decodes Alice and Bobs messages 
        mallory_secret_bytes = str(1).encode('utf-8')
        mallory_secret_key = hashlib.sha256(mallory_secret_bytes).hexdigest()[:16]
        print(f"Mallory hashed secret key: {mallory_secret_key}")
        mallory_cipher_1 = AES.new(mallory_secret_key.encode('utf-8'), AES.MODE_CBC, iv)
        mallory_cipher_2 = AES.new(mallory_secret_key.encode('utf-8'), AES.MODE_CBC, iv)
        # Decrypt messages using AES-CBC and mallorys secret key      
        alice_message_decoded = unpad(mallory_cipher_1.decrypt(alice_message_ciphertext), AES.block_size).decode()
        bob_message_decoded = unpad(mallory_cipher_2.decrypt(bob_message_ciphertext), AES.block_size).decode()
        
        print(f"Mallory Decoded Alice Message: {alice_message_decoded}")
        print(f"Mallory Decoded Bob Message: {bob_message_decoded}")

    return

if __name__ == "__main__":
    main()