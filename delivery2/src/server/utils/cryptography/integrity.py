from cryptography.hazmat.primitives import hashes, hmac

# -------------------------------

def calculate_digest(data: bytes, key: bytes) -> bytes:
    """Calculate the digest of the data using SHA256 algorithm
    
    Args:
        data (bytes): Data to be hashed
        key (bytes): Key to hash the data
        
    Returns:
        bytes: Hashed data
    """
    
    digest = hmac.HMAC(key, hashes.SHA256())
    digest.update(data)    
    
    return digest.finalize()

# -------------------------------

def verify_digest(data: bytes, digest: bytes, key: bytes) -> bool:
    """Verify the integrity of the data

    Args:
        data (bytes): Data to be verified
        digest (bytes): Digest to compare with the calculated digest
        key (bytes): Key to hash the data
        
    Returns:
        bool: True if the data is valid, False otherwise
    """
    
    new_digest = calculate_digest(data, key)
    
    return new_digest == digest
