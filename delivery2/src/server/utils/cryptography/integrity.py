from cryptography.hazmat.primitives import hashes

# -------------------------------

def calculate_digest(data: str) -> bytes:
    """Calculate the digest of the data using SHA256 algorithm

    Args:
        data (str): Data to be hashed

    Returns:
        bytes: Hashed data
    """
    
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)

    return digest.finalize()

# -------------------------------

def verify_digest(data: str, digest: str):
    """Verify the integrity of the data

    Args:
        data (str): Data to be verified
        digest (str): Digest to compare with the calculated digest
        
    Returns:
        bool: True if the data is valid, False otherwise
    """
    
    dataDigest = calculate_digest(data);
    return digest == dataDigest 
