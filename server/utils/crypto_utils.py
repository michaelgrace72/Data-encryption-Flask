from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import base64
import binascii

# Key Generation
def generate_user_keypair():
    """Generate a new RSA key pair."""
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return public_key, private_key

# AES Key Validation and Conversion
def check_key_length(user_key):
    """Ensure the AES key is 32 bytes. Convert from hex if needed."""
    if isinstance(user_key, str) and len(user_key) == 64:
        user_key = binascii.unhexlify(user_key)  # Convert hex to binary (32 bytes)
    elif len(user_key) != 32:
        raise ValueError("AES key must be 32 bytes for AES-256 encryption.")
    return user_key

# Encrypt Private Key with AES
def encrypt_private_key(private_key, user_key):
    """Encrypt the RSA private key using the user's AES key."""
    user_key = check_key_length(user_key)  # Validate AES key
    cipher = AES.new(user_key, AES.MODE_EAX)
    nonce = cipher.nonce
    encrypted_data = cipher.encrypt(private_key)
    # Combine nonce and encrypted data, then encode in Base64 for storage
    encrypted_private_key_b64 = base64.b64encode(nonce + encrypted_data).decode('utf-8')
    return encrypted_private_key_b64

# Decrypt Private Key
def decrypt_private_key(encrypted_private_key_b64, user_key):
    """Decrypt the RSA private key using the user's AES key."""
    user_key = check_key_length(user_key)  # Validate AES key
    # Decode the Base64 string to get back binary encrypted data
    encrypted_data = base64.b64decode(encrypted_private_key_b64)
    nonce = encrypted_data[:16]
    cipher = AES.new(user_key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt(encrypted_data[16:])

# Sign PDF Hash with RSA Private Key
def sign_pdf_hash(pdf_data, private_key):
    """Sign the hash of PDF content using the RSA private key."""
    pdf_hash = SHA256.new(pdf_data)
    signer = pkcs1_15.new(RSA.import_key(private_key))
    signature = signer.sign(pdf_hash)
    return base64.b64encode(signature).decode('utf-8')  # Return Base64-encoded signature

# Verify PDF Hash with RSA Public Key
def verify_pdf_signature(pdf_data, signature_b64, public_key):
    """Verify the PDF hash with the RSA public key and provided signature."""
    pdf_hash = SHA256.new(pdf_data)
    verifier = pkcs1_15.new(RSA.import_key(public_key))
    try:
        verifier.verify(pdf_hash, base64.b64decode(signature_b64))
        return True
    except (ValueError, TypeError):
        return False
