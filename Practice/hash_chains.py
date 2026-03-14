import hashlib

def compute_root_hash(blocks):
    """
    input: list of bytes objects
    output: hex string of h0
    """

    # Start with last block
    current_hash = hashlib.sha256(blocks[-1]).digest()

    # Process backwards
    for i in range(len(blocks) - 2, -1, -1):
        block = blocks[i]
        current_hash = hashlib.sha256(block + current_hash).digest()

    return current_hash.hex()

def verify_stream(blocks, trusted_h0):
    """
    blocks: list of bytes objects (each block includes appended hash except last)
    trusted_h0: hex string
    """

    expected_hash_hex = trusted_h0

    for i in range(len(blocks)):
        block = blocks[i]

        # Hash the entire block
        computed_hash_hex = hashlib.sha256(block).hexdigest()

        # Compare with expected hash
        if computed_hash_hex != expected_hash_hex:
            return False

        # If not last block, extract trailing 32 bytes to verify next block
        if i < len(blocks) - 1:
            expected_hash_hex = block[-32:].hex()

    return True

#  Test Case 1 
blocks_hex = [
    "48656c6c6f20",   # "Hello "
    "576f726c64",     # "World"
    "21"              # "!"
]

blocks = [bytes.fromhex(b) for b in blocks_hex]

print("Test Case 1: Computed Root Hash = " + compute_root_hash(blocks))

#  Test Case 2 
stream_data_hex = [
    "5365637572697479e760f249914465825e27d0c6f6110637307eac934fc225749bfe75324df5db2e",
    "20697320c960563f683a14202dc212ae6554753a03c6cd6ab9df8c27ebd818ba848ab9ef",
    "46756e"
]

stream_data = [bytes.fromhex(b) for b in stream_data_hex]

trusted_h0 = "f11afac36abee3f8be106bc53226012250cad05b2d3ee621bb5857ff94d92d65"

valid = verify_stream(stream_data, trusted_h0)

print("Test Case 2:", "Stream Valid" if valid else "Stream Tampered")
