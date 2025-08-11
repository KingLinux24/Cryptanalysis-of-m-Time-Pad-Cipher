#Assignment 3 : Cryptanalysis of m-Time pad cipher                                                        
# Given are seven cipher texts (represented in hex) encrypted using m-time pads. m>1 (repeating same key) destroys security of one-time pad. Could you find out which cipher texts are encrypted using same key?

#Hint#1. These cipher texts are resulted from plain texts written in English. 
#Hint#2. There are multiple sets of cipher texts encrypted using same key(s)



import binascii

# Given ciphertexts in hex
ciphertexts_hex = {
    'C1': "cbe9e6a8e0eda8f8faedece1ebfca8fce0eda8eaede0e9fee1e7fdfaa8e7eea8fce0e1fba8eae1efa8ece7efa8e7eea8c9beb7a8e7eea8fce0eda8f1ede9faaa6a6bab8b9baa6",
    'C2': "dbe9ebe0e1e6eda8e7faa8c4e9fae9b7a8a8dfe0e7a8e1fba8fce0eda8eaedfbfca8f8e4e9f1edfaa8e7eea8ebfae1ebe3edfcb7",
    'C3': "ffe0e9fca8ece7a8f1e7fda8fce0e1e6e3a4a8c1e6ece1e9a8ebe9e6a8e6e7fca8fbe1efe6a8fce0eda8f8e9ebfca8ffe1fce0a8fce0eda8dddbc9b7",
    'C4': "445b524713575c134a5c4613475b5a5d581f137a5d575a521350525d135d5c4713405a545d13475b56134352504713445a475b13475b56136660720c",
    'C5': "3d3a2275213a75363427272c753a202175213d3c2675302d2530273c38303b21753a3375383c2d3c3b3275213d273030753234263026753421753d3c323d752273026262027307b",
    'C6': "393a233075393a233075393a233075223d3a75223c393975373075213d307526212031303b21753a3375213d30752c3034277b7b7b14383c27753a27750634338343b7b",
    'C7': "ffeda8ebe9e6a8e6e7fca8f8faedece1ebfca8fce0eda8eaede0e9fee1e7fdfaa8e7eea8fce0e1fba8eae1efa8ece7efa8e7eea8c9bea6a8e7eea8fce0eda8fede9faa6a6a6bab8b9baa6"
}

def hex_to_bytes(hex_str):
    # Fix odd-length hex strings by padding with a trailing zero if needed
    if len(hex_str) % 2 != 0:
        hex_str += '0'
    return binascii.unhexlify(hex_str)

def xor_bytes(b1, b2):
    return bytes([x ^ y for x, y in zip(b1, b2)])

def is_likely_space(xored_byte):
    # In English texts, space (0x20) XOR with alphabetic characters results in bytes in range 0x41-0x7A (A-z)
    # So if XORed byte is in this range, it might indicate one of the plaintexts had a space at that position
    return (0x41 <= xored_byte <= 0x7A)

def analyze_ciphertexts(ciphertexts):
    # Convert hex to bytes
    ctexts_bytes = {k: hex_to_bytes(v) for k, v in ciphertexts.items()}
    keys_groups = []
    used = set()

    # Compare each pair of ciphertexts
    for c1 in ctexts_bytes:
        if c1 in used:
            continue
        group = [c1]
        b1 = ctexts_bytes[c1]
        for c2 in ctexts_bytes:
            if c2 == c1 or c2 in used:
                continue
            b2 = ctexts_bytes[c2]
            length = min(len(b1), len(b2))
            xored = xor_bytes(b1[:length], b2[:length])
            # Count positions where XORed byte likely indicates space in one plaintext
            space_like_count = sum(is_likely_space(b) for b in xored)
            # Heuristic threshold: if many positions indicate space, likely same key
            if space_like_count > length * 0.3:  # 30% threshold
                group.append(c2)
        if len(group) > 1:
            keys_groups.append(group)
            used.update(group)
        else:
            # Single ciphertext with unique key
            keys_groups.append([c1])
            used.add(c1)
    return keys_groups

def main():
    groups = analyze_ciphertexts(ciphertexts_hex)
    print("Groups of ciphertexts encrypted with the same key:")
    for i, group in enumerate(groups, 1):
        print(f"Group {i}: {', '.join(group)}")

if __name__ == "__main__":
    main()
