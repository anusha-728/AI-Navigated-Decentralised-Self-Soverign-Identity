import base64
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature

def generate_keypair():
    """Generates an Ed25519 private and public key pair for SSI node identity."""
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    
    return {
        "private_key": base64.b64encode(private_key.private_bytes_raw()).decode('utf-8'),
        "public_key": base64.b64encode(public_key.public_bytes_raw()).decode('utf-8')
    }

def sign_nonce(private_key_b64: str, nonce: str) -> str:
    """Signs a challenge nonce using the node's Ed25519 private key."""
    priv_bytes = base64.b64decode(private_key_b64)
    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(priv_bytes)
    signature = private_key.sign(nonce.encode('utf-8'))
    return base64.b64encode(signature).decode('utf-8')

def verify_signature(public_key_b64: str, nonce: str, signature_b64: str) -> bool:
    """Verifies an Ed25519 signature against a node's public key and nonce."""
    try:
        pub_bytes = base64.b64decode(public_key_b64)
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)
        signature = base64.b64decode(signature_b64)
        public_key.verify(signature, nonce.encode('utf-8'))
        return True
    except InvalidSignature:
        return False
    except Exception as e:
        print(f"Error during signature verification: {e}")
        return False