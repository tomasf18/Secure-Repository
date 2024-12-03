from cryptography.hazmat.primitives import hashes

# -------------------------------

def calculate_digest(data: str):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)

    return digest.finalize()

# -------------------------------

def verify_digest(data: str, digest: str):
    dataDigest = calculate_digest(data);

    return digest == dataDigest 
