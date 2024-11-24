from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.x509 import (
    CertificateBuilder,
    Name,
    NameAttribute,
    random_serial_number,
)
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.serialization import pkcs12

def generate_certificate_no_password(output_path):
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Define subject and issuer
    subject = issuer = Name([
        NameAttribute(NameOID.COUNTRY_NAME, "ID"),
        NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Jawa Timur"),
        NameAttribute(NameOID.LOCALITY_NAME, "Surabaya"),
        NameAttribute(NameOID.ORGANIZATION_NAME, "Figuran"),
        NameAttribute(NameOID.COMMON_NAME, "Alvnvnc"),
    ])

    # Build certificate
    certificate = CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=365)  # Valid for 1 year
    ).sign(private_key, hashes.SHA256())

    # Generate PKCS12 file without encryption (no password)
    p12_data = pkcs12.serialize_key_and_certificates(
        name=b'my_key_certificate_bundle',
        key=private_key,
        cert=certificate,
        cas=None,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Save PKCS12 file
    p12_path = f"{output_path}/certificate_no_password.p12"
    with open(p12_path, "wb") as p12_file:
        p12_file.write(p12_data)
    print(f"PKCS#12 file saved to: {p12_path}")

    return p12_path

# Example usage
if __name__ == "__main__":
    import os

    # Specify output directory
    output_dir = "certificates"
    os.makedirs(output_dir, exist_ok=True)

    p12_file = generate_certificate_no_password(output_dir)
    print(f"PKCS#12 file generated successfully!")
    print(f"PKCS#12 File: {p12_file}")
