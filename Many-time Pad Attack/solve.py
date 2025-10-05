import os
import sys

CIPHERTEXTS_HEX = [
    "315c4eeaa8b5f8aaf9174145bf43e1784b8fa00dc71d885a804e5ee9fa40b16349c146fb778cdf2d3aff021dfff5b403b510d0d0455468aeb98622b137dae857553ccd8883a7bc37520e06e515d22c954eba5025b8cc57ee59418ce7dc6bc41556bdb36bbca3e8774301fbcaa3b83b220809560987815f65286764703de0f3d524400a19b159610b11ef3e",
    "234c02ecbbfbafa3ed18510abd11fa724fcda2018a1a8342cf064bbde548b12b07df44ba7191d9606ef4081ffde5ad46a5069d9f7f543bedb9c861bf29c7e205132eda9382b0bc2c5c4b45f919cf3a9f1cb74151f6d551f4480c82b2cb24cc5b028aa76eb7b4ab24171ab3cdadb8356f",
    "32510ba9a7b2bba9b8005d43a304b5714cc0bb0c8a34884dd91304b8ad40b62b07df44ba6e9d8a2368e51d04e0e7b207b70b9b8261112bacb6c866a232dfe257527dc29398f5f3251a0d47e503c66e935de81230b59b7afb5f41afa8d661cb",
    "32510ba9aab2a8a4fd06414fb517b5605cc0aa0dc91a8908c2064ba8ad5ea06a029056f47a8ad3306ef5021eafe1ac01a81197847a5c68a1b78769a37bc8f4575432c198ccb4ef63590256e305cd3a9544ee4160ead45aef520489e7da7d835402bca670bda8eb775200b8dabbba246b130f040d8ec6447e2c767f3d30ed81ea2e4c1404e1315a1010e7229be6636aaa",
    "3f561ba9adb4b6ebec54424ba317b564418fac0dd35f8c08d31a1fe9e24fe56808c213f17c81d9607cee021dafe1e001b21ade877a5e68bea88d61b93ac5ee0d562e8e9582f5ef375f0a4ae20ed86e935de81230b59b73fb4302cd95d770c65b40aaa065f2a5e33a5a0bb5dcaba43722130f042f8ec85b7c2070",
    "32510bfbacfbb9befd54415da243e1695ecabd58c519cd4bd2061bbde24eb76a19d84aba34d8de287be84d07e7e9a30ee714979c7e1123a8bd9822a33ecaf512472e8e8f8db3f9635c1949e640c621854eba0d79eccf52ff111284b4cc61d11902aebc66f2b2e436434eacc0aba938220b084800c2ca4e693522643573b2c4ce35050b0cf774201f0fe52ac9f26d71b6cf61a711cc229f77ace7aa88a2f19983122b11be87a59c355d25f8e4",
    "32510bfbacfbb9befd54415da243e1695ecabd58c519cd4bd90f1fa6ea5ba47b01c909ba7696cf606ef40c04afe1ac0aa8148dd066592ded9f8774b529c7ea125d298e8883f5e9305f4b44f915cb2bd05af51373fd9b4af511039fa2d96f83414aaaf261bda2e97b170fb5cce2a53e675c154c0d9681596934777e2275b381ce2e40582afe67650b13e72287ff2270abcf73bb028932836fbdecfecee0a3b894473c1bbeb6b4913a536ce4f9b13f1efff71ea313c8661dd9a4ce",
    "315c4eeaa8b5f8bffd11155ea506b56041c6a00c8a08854dd21a4bbde54ce56801d943ba708b8a3574f40c00fff9e00fa1439fd0654327a3bfc860b92f89ee04132ecb9298f5fd2d5e4b45e40ecc3b9d59e9417df7c95bba410e9aa2ca24c5474da2f276baa3ac325918b2daada43d6712150441c2e04f6565517f317da9d3",
    "271946f9bbb2aeadec111841a81abc300ecaa01bd8069d5cc91005e9fe4aad6e04d513e96d99de2569bc5e50eeeca709b50a8a987f4264edb6896fb537d0a716132ddc938fb0f836480e06ed0fcd6e9759f40462f9cf57f4564186a2c1778f1543efa270bda5e933421cbe88a4a52222190f471e9bd15f652b653b7071aec59a2705081ffe72651d08f822c9ed6d76e48b63ab15d0208573a7eef027",
    "466d06ece998b7a2fb1d464fed2ced7641ddaa3cc31c9941cf110abbf409ed39598005b3399ccfafb61d0315fca0a314be138a9f32503bedac8067f03adbf3575c3b8edc9ba7f537530541ab0f9f3cd04ff50d66f1d559ba520e89a2cb2a83",
    "32510ba9babebbbefd001547a810e67149caee11d945cd7fc81a05e9f85aac650e9052ba6a8cd8257bf14d13e6f0a803b54fde9e77472dbff89d71b57bddef121336cb85ccb8f3315f4b52e301d16e9f52f904"
]

TARGET_CIPHERTEXT_INDEX = len(CIPHERTEXTS_HEX) - 1 

SCORING_TABLE = {
    b' ': 10, b'e': 9, b't': 8, b'a': 7, b'o': 7, b'i': 7, b'n': 7,
    b's': 6, b'h': 6, b'r': 6, b'd': 5, b'l': 5, b'u': 5,
}
for i in range(32, 127):
    char = bytes([i])
    if char.isalpha() and char.lower() not in SCORING_TABLE:
        SCORING_TABLE[char.lower()] = 3
    elif char.isdigit():
        SCORING_TABLE[char] = 2
    elif char in b'.,!?;:\'"()[]{}':
        SCORING_TABLE[char] = 1

#Attack method
def score_text(byte_string):
    """Scores a byte string based on character frequency."""
    score = 0
    for byte in byte_string:
        char = bytes([byte])
        score += SCORING_TABLE.get(char.lower(), -5)
        if not (32 <= byte <= 126):
            score -= 10
    return score

def solve_many_time_pad(ciphertexts, target_index):
    """
    Automates the initial pass of the attack, continuing as long as
    at least two ciphertexts are available.
    """
    if not ciphertexts or not (0 <= target_index < len(ciphertexts)):
        raise ValueError("Invalid target index or empty ciphertext list.")

    #Only solve for the lenght of the target ciphertext 
    target_ciphertext = ciphertexts[target_index]
    target_len = len(target_ciphertext)
    key = bytearray(target_len)

    for i in range(target_len):
        ciphertexts_at_pos_i = [c for c in ciphertexts if i < len(c)]
        
        if len(ciphertexts_at_pos_i) < 2:
            print(f"\n[*] Automated guessing stopped at position {i} due to insufficient overlapping ciphertexts.")
            for j in range(i, target_len):
                key[j] = 0  
            break

        best_guess_for_key_byte = 0
        highest_score = -float('inf')

        for key_byte_guess in range(256):
            decrypted_column = bytearray(c[i] ^ key_byte_guess for c in ciphertexts_at_pos_i)
            current_score = score_text(decrypted_column)
            
            if current_score > highest_score:
                highest_score = current_score
                best_guess_for_key_byte = key_byte_guess
        
        key[i] = best_guess_for_key_byte

        if (i + 1) % 10 == 0 or i == target_len - 1:
            sys.stdout.flush()


    plaintexts = []
    for c in ciphertexts:
        decrypt_len = min(len(c), target_len)
        plaintexts.append(bytearray(c[j] ^ key[j] for j in range(decrypt_len)))

    return key, plaintexts

def display_state(plaintexts, target_index):
    """Displays the current state of the decrypted plaintexts."""
    os.system('cls' if os.name == 'nt' else 'clear')
    print("=" * 80)
    print("INTERACTIVE REFINEMENT MODE")
    print("=" * 80)
    print("Enter 'msg_idx,char_pos,new_char' to make a correction.")
    print("Example: '3,15,e' means plaintext 3, position 15, should be 'e'.")
    print("Enter 'quit' or 'exit' to finish.")
    print("-" * 80)

    max_len = len(plaintexts[target_index])
    
    tens = " " * 12
    units = " " * 12
    for i in range(max_len):
        tens += str(i // 10) if i % 10 == 0 else " "
        units += str(i % 10)
    print(tens)
    print(units)
    print("-" * (max_len + 12))

    for i, p in enumerate(plaintexts):
        prefix = ">> TARGET" if i == target_index else f"   P {i}"
        decoded_p = p.decode('utf-8', 'replace').replace('\n', ' ')
        print(f"{prefix:10}: {decoded_p}")
    print("-" * 80)

def interactive_refinement_loop(key, plaintexts, ciphertexts, target_index):
    target_len = len(ciphertexts[target_index])

    while True:
        display_state(plaintexts, target_index)
        
        try:
            user_input = input("Enter correction (or 'quit'): ").strip().lower()
            if user_input in ['quit', 'exit']:
                break
            
            parts = user_input.split(',')
            if len(parts) != 3:
                print("[!] Invalid format. Please use 'msg_idx,char_pos,new_char'.")
                input("Press Enter to continue...")
                continue
            
            msg_idx, char_pos, new_char = int(parts[0]), int(parts[1]), parts[2]

            if not (0 <= msg_idx < len(plaintexts)):
                print(f"[!] Message index must be between 0 and {len(plaintexts)-1}.")
                input("Press Enter to continue...")
                continue
            if not (0 <= char_pos < target_len):
                print(f"[!] Character position must be between 0 and {target_len-1}.")
                input("Press Enter to continue...")
                continue
            if not (char_pos < len(ciphertexts[msg_idx])):
                print(f"[!] Position {char_pos} is out of bounds for message {msg_idx} (length {len(ciphertexts[msg_idx])}).")
                input("Press Enter to continue...")
                continue
            if len(new_char) != 1:
                print("[!] Please provide a single character.")
                input("Press Enter to continue...")
                continue

            new_char_byte = ord(new_char)
            c_user = ciphertexts[msg_idx]
            new_key_byte = c_user[char_pos] ^ new_char_byte
            key[char_pos] = new_key_byte
            
            for i in range(len(plaintexts)):
                if char_pos < len(ciphertexts[i]):
                    plaintexts[i][char_pos] = ciphertexts[i][char_pos] ^ new_key_byte

        except (ValueError, IndexError) as e:
            print(f"[!] Invalid input: {e}. Please follow the format.")
            input("Press Enter to continue...")

    return key, plaintexts

# --- Main ---
def main():
    try:
        ciphertexts = [bytes.fromhex(ct.strip()) for ct in CIPHERTEXTS_HEX]
        target_index = TARGET_CIPHERTEXT_INDEX
    except Exception as e:
        print(f"[!] Error loading ciphertexts from code: {e}")
        return

    # Validation
    if not (0 <= target_index < len(ciphertexts)):
        print(f"[!] Error: Target index {target_index} is out of bounds (0-{len(ciphertexts)-1}).")
        return

    try:
        initial_key, initial_plaintexts = solve_many_time_pad(ciphertexts, target_index)
    except Exception as e:
        print(f"[!] An error occurred during the automated attack: {e}")
        return

    final_key, final_plaintexts = interactive_refinement_loop(
        initial_key, initial_plaintexts, ciphertexts, target_index
    )

    print("\n" + "="*60)
    print("FINAL RESULTS")
    print("="*60)
    print(f"\n[+] Final Recovered Key (hex):\n{final_key.hex()}")
    print("\n[+] Final Decrypted Plaintexts:")
    for i, p in enumerate(final_plaintexts):
        prefix = ">> TARGET" if i == target_index else f"   P {i}"
        print(f"{prefix}: {p.decode('utf-8', 'replace')}")
    print("\n" + "="*60)

if __name__ == "__main__":
    main()