import io
from PyPDF2 import PdfReader
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding


def verify_pdf_signature(signed_pdf_path, certificate_path):
    """
    Verifies the digital signature in the PDF file using the public key from the certificate.

    Args:
        signed_pdf_path (str): Path to the signed PDF file.
        certificate_path (str): Path to the PKCS#12 certificate.

    Returns:
        bool: True if the signature is valid, False otherwise.
    """
    try:
        # Load the signed PDF
        reader = PdfReader(signed_pdf_path)

        # Extract metadata
        metadata = reader.metadata
        if not metadata or '/Signature' not in metadata:
            print("No digital signature found in the PDF metadata.")
            return False

        signature_hex = metadata.get('/SignatureContents', None)
        if not signature_hex:
            print("No signature contents found in the metadata.")
            return False

        signature_bytes = bytes.fromhex(signature_hex)

        # Extract the PDF content
        with open(signed_pdf_path, 'rb') as f:
            pdf_content = f.read()

        # Load the certificate to get the public key
        with open(certificate_path, 'rb') as cert_file:
            p12_data = cert_file.read()

        # Load PKCS#12 certificate
        private_key, certificate, _ = serialization.load_key_and_certificates(
            p12_data, b"MySafePass"
        )

        # Extract public key from the certificate
        public_key = certificate.public_key()

        # Verify the signature
        public_key.verify(
            signature_bytes,
            pdf_content,
            padding.PKCS1v15(),
            hashes.SHA256()
        )

        print("The digital signature is valid.")
        return True
    except Exception as e:
        print(f"Signature verification failed: {e}")
        return False


if __name__ == "__main__":
    # Define the paths
    signed_pdf_path = "tes2.pdf"  # Replace with your signed PDF path
    certificate_path = "certificates/certificate_no_password.p12"  # Path to your PKCS#12 certificate

    # Verify the signature
    is_valid = verify_pdf_signature(signed_pdf_path, certificate_path)
    if is_valid:
        print("Signature verification passed!")
    else:
        print("Signature verification failed.")
