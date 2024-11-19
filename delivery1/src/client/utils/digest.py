from cryptography.hazmat.primitives import hashes

def calculateDigest(data: str):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)

    return digest.finalise()

def verifyDigest(data: str, digest: str):
    dataDigest = calculateDigest(data);

    return digest == dataDigest 
