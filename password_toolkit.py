import json
import os
import re
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from rbloom import Bloom
import math
import argparse
import time


def create_parser():
    parser = argparse.ArgumentParser()
    subparser = parser.add_subparsers(title="Available Commands", dest="command")

    # Check password
    parser_check = subparser.add_parser(
        "check-password", help="Checks the strength of a given password."
    )
    parser_check.add_argument(
        "--password", "-p", required=True, help="The password string to check."
    )

    # Create user
    parser_create_user = subparser.add_parser("create-user", help="Creates a new user.")
    parser_create_user.add_argument(
        "--username", "-u", required=True, help="The username for the new user."
    )
    parser_create_user.add_argument(
        "--password", "-p", required=True, help="The password for the new user."
    )

    # Build bloom filter
    parser_build_bloom = subparser.add_parser(
        "build-bloom", help="Builds a bloom filter from a blacklist file."
    )
    parser_build_bloom.add_argument(
        "--blacklist",
        required=True,
        help="Path to the blacklist file (e.g., data/blacklist.txt).",
    )
    parser_build_bloom.add_argument(
        "--out",
        required=True,
        help="Path to save the bloom filter (e.g., data/bloom.bin).",
    )

    # Encrypt file
    parser_encrypt = subparser.add_parser("encrypt-file", help="Encrypts a file.")
    parser_encrypt.add_argument(
        "--username", "-u", required=True, help="Username for encryption."
    )
    parser_encrypt.add_argument(
        "--password", "-p", required=True, help="Password for encryption."
    )
    parser_encrypt.add_argument(
        "--infile", required=True, help="Input file to encrypt."
    )
    parser_encrypt.add_argument(
        "--outfile", required=True, help="Output file for encrypted data."
    )

    # Decrypt file
    parser_decrypt = subparser.add_parser("decrypt-file", help="Decrypts a file.")
    parser_decrypt.add_argument(
        "--username", "-u", required=True, help="Username for decryption."
    )
    parser_decrypt.add_argument(
        "--password", "-p", required=True, help="Password for decryption."
    )
    parser_decrypt.add_argument(
        "--infile", required=True, help="Input file to decrypt."
    )
    parser_decrypt.add_argument(
        "--outfile", required=True, help="Output file for decrypted data."
    )

    # Simulate crack
    parser_simulate_crack = subparser.add_parser(
        "simulate-crack", help="Simulates cracking passwords from a dictionary."
    )
    parser_simulate_crack.add_argument(
        "--dict",
        required=True,
        help="Path to the dictionary file (e.g., data/small_dict.txt).",
    )

    # Check bloom filter
    parser_check_bloom = subparser.add_parser(
        "check-bloom", help="Checks if a password is in a bloom filter."
    )
    parser_check_bloom.add_argument(
        "--bloom",
        required=True,
        help="Path to the bloom filter file (e.g., data/bloom.bin).",
    )
    parser_check_bloom.add_argument(
        "--password", "-p", required=True, help="Password to check."
    )

    # Verify user
    parser_verify_user = subparser.add_parser("verify-user", help="Verifies a user.")
    parser_verify_user.add_argument(
        "--username", "-u", required=True, help="Username to verify."
    )
    parser_verify_user.add_argument(
        "--password", "-p", required=True, help="Password to verify."
    )
    parser_verify_user.add_argument(
        "--users-file",
        "-f",
        required=False,
        default="data/sample_users.json",
        help="Path to the users file (e.g., data/sample_users.json).",
    )

    return parser


def password_meter(password):
    ratings = ["weak", "fair", "good", "strong"]
    rating = ""
    suggestion = []

    entropy = check_entropy(password)

    if entropy < 30:
        rating = ratings[0]
    elif entropy < 40:
        rating = ratings[1]
    elif entropy < 60:
        rating = ratings[2]
    else:
        rating = ratings[3]

    # detect repitition
    single_char_pattern = re.compile(r"(.)\1{2}")
    if single_char_pattern.search(password):
        suggestion.append("Avoid repeated characters")
    # detect sequences
    if check_simple_sequence(password):
        suggestion.append("Avoid sequences of characters (123, abc, etc)")

    if check_common_substring(password):
        suggestion.append("Avoid common substrings")

    if check_for_year(password):
        suggestion.append("Avoid using years in your password")

    print(f"Your password has {entropy:.3f} bits of entropy, your rating is: {rating}.")
    
    if suggestion:
        print("Suggestions:")
        for i, suggestion_item in enumerate(suggestion, 1):
            print(f"  {i}. {suggestion_item}")
    else:
        print("No specific suggestions - your password looks good!")


def check_simple_sequence(password, min_length=3):
    n = len(password)

    for i in range(n - min_length + 1):
        substring = password[i : i + min_length]

        # Check for ascending sequence (e.g., '1', '2', '3' or 'a', 'b', 'c')
        is_ascending = all(
            ord(substring[j]) == ord(substring[j - 1]) + 1
            for j in range(1, len(substring))
        )

        # Check for descending sequence (e.g., '3', '2', '1' or 'c', 'b', 'a')
        is_descending = all(
            ord(substring[j]) == ord(substring[j - 1]) - 1
            for j in range(1, len(substring))
        )

        if is_ascending or is_descending:
            return True, substring  # Sequence found

    return False


def check_entropy(password):
    length = len(password)
    range = 0

    specialChars = r"""!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~"""
    hasDigit = any(char.isdigit() for char in password)
    hasUpper = any(char.isupper() for char in password)
    hasLower = any(char.islower() for char in password)
    hasSpe = any(char in specialChars for char in password)

    if hasUpper:
        range += 26  # 26 uppercase characters
    if hasLower:
        range += 26  # 26 lowercase characters
    if hasDigit:
        range += 10  # 10 digits
    if hasSpe:
        range += len(specialChars)  # custom range depending on the list

    return length * math.log2(range)  # using formula E = L*log2(R)


def check_common_substring(password):
    common_substrings = [
        "qwerty",
        "yuiop",
        "asdfg",
        "ghjkl",
        "zxcvb",
        "bnm",
        "trewq",
        "poiuy",
        "lkjhg",
        "mnbvc",
        "qaz",
        "wsx",
        "edc",
        "rfv",
        "tgb",
        "12345",
        "54321",
        "67890",
        "09876",
    ]
    password_lower = password.lower()

    for sequence in common_substrings:
        if sequence in password_lower:
            return True, sequence  # Sequence found

    return False


def check_for_year(password):
    for year in range(1900, 2100):
        if str(year) in password:
            return True
    return False


def create_user(username, password, iterations=600_000):
    print(f"Creating user: {username}")
    salt = get_random_bytes(16)
    key = PBKDF2(password, salt, dkLen=32, count=iterations, hmac_hash_module=SHA256)

    user_data = {
        "username": username,
        "pwd_salt_hex": salt.hex(),
        "pwd_hash_hex": key.hex(),
        "pwd_iterations": iterations,
    }

    save_user(user_data, "data/sample_users.json")
    return user_data


def save_user(user_data, filename):
    data = {}
    if os.path.exists(filename):
        with open(filename, "r") as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError:
                data = {}  # Handle empty or corrupt file

    data[user_data.get("username")] = user_data

    os.makedirs(os.path.dirname(filename), exist_ok=True)

    with open(filename, "w") as f:
        json.dump(data, f, indent=4)

    print(
        f"Successfully hashed and stored data for user '{user_data.get('username')}' in {filename}"
    )
    return user_data


def build_bloom(blacklist_file, out_file):
    if not os.path.exists(blacklist_file):
        print(f"Blacklist file not found: {blacklist_file}")
        return
    bloom_filter = Bloom(
        100_000, 0.01, hash_func=hash_func
    )  # 100,000 items expected, false positive rate of 0.01
    with open(blacklist_file, "r") as f:
        for line in f:
            line = line.strip()
            bloom_filter.add(line)

    bloom_filter.save(out_file)

    print(f"Bloom filter saved to {out_file}")

    return bloom_filter


def hash_func(password):
    h = SHA256.new()
    h.update(password.encode("utf-8"))
    return int.from_bytes(h.digest()[:16], "big", signed=True)


def check_bloom(bloom_file, password):
    if not os.path.exists(bloom_file):
        print(f"Bloom filter file not found: {bloom_file}")
        return
    bloom_filter = Bloom.load(bloom_file, hash_func=hash_func)
    if password in bloom_filter:
        print(f"Password '{password}' is in the bloom filter.")
    else:
        print(f"Password '{password}' is not in the bloom filter.")
    return password in bloom_filter


def simulate_crack(dictionary_file, users_file="data/sample_users.json"):
    # Checking files exist
    if not os.path.exists(users_file):
        print(f"Users file not found: {users_file}")
        return

    with open(users_file, "r") as f:
        try:
            users = json.load(f)
        except json.JSONDecodeError:
            print(f"Users file is empty or corrupt: {users_file}")
            return

    if not isinstance(users, dict) or not users:
        print("No users to test.")
        return

    if not os.path.exists(dictionary_file):
        print(f"Dictionary file not found: {dictionary_file}")
        return

    start_time = time.time()
    cracked = {}
    attempted = 0

    with open(dictionary_file, "r", encoding="utf-8", errors="ignore") as dict_f:
        candidates = [line.strip() for line in dict_f if line.strip()]

    # Checking number of users and candidates
    total_users = len(users)
    print(f"Loaded {len(candidates)} candidates for {total_users} user(s).", flush=True)

    # Cracking users
    for idx, (username, data) in enumerate(users.items(), start=1):
        print(f"[{idx}/{total_users}] Cracking user '{username}'...", flush=True)
        # Getting user data
        salt_hex = data.get("pwd_salt_hex")
        hash_hex = data.get("pwd_hash_hex")
        iterations = data.get("pwd_iterations")

        if not salt_hex or not hash_hex or not iterations:
            continue  # If user data is not complete, skip

        salt = bytes.fromhex(salt_hex)  # Converting salt from hex to bytes
        target = hash_hex.lower()  # Converting hash from hex to lowercase

        found = None
        for candidate in candidates:  # Trying each candidate hash
            attempted += 1
            key = PBKDF2(
                candidate,
                salt,
                dkLen=32,
                count=int(iterations),
                hmac_hash_module=SHA256,
            )
            if key.hex().lower() == target:
                found = candidate
                break
            if attempted % 50000 == 0:  # Printing progress every 50,000 attempts
                elapsed_partial = time.time() - start_time
                print(
                    f"Progress: attempted {attempted} hashes in {elapsed_partial:.1f}s...",
                    flush=True,
                )

        cracked[username] = found
        if found is None:  # If user is not cracked
            print(f"[{idx}/{total_users}] User '{username}' not cracked.", flush=True)
        else:
            print(
                f"[{idx}/{total_users}] User '{username}' cracked.", flush=True
            )  # If user is cracked

    elapsed = time.time() - start_time
    num_cracked = sum(1 for v in cracked.values() if v is not None)

    # Printing results
    print(
        f"Tried {attempted} candidate hashes across {total_users} users in {elapsed:.2f}s."
    )
    print(f"Cracked {num_cracked}/{total_users} users.")
    for user, pwd in cracked.items():  # Printing cracked users
        if pwd is None:
            print(f"{user}: NOT CRACKED")
        else:
            print(f"{user}: '{pwd}'")

    return cracked


def encrypt_file(username, password, infile, outfile):
    print(f"Encrypting file: {infile}")
    print(f"Output file: {outfile}")
    
    start_time = time.time()

    # Derive encryption key from password using PBKDF2-HMAC-SHA256
    salt = get_random_bytes(16)  # 128-bit salt
    key = PBKDF2(
        password, salt, dkLen=32, count=10**7, hmac_hash_module=SHA256
    )  # 32 bytes = 256 bits

    # AES-GCM with a 96-bit nonce
    nonce = get_random_bytes(12)  # 12 bytes = 96 bits
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

    # Use the username as AAD
    aad = username.encode("utf-8")
    cipher.update(aad)

    with open(infile, "rb") as f:
        plaintext = f.read()

    ciphertext = cipher.encrypt(plaintext)
    tag = cipher.digest()  # Get the tag from the cipher

    # File format: b"AES-GCM" | salt(16) | nonce(12) | tag(16) | ciphertext
    with open(outfile, "wb") as f:
        f.write(b"AES-GCM")
        f.write(salt)
        f.write(nonce)
        f.write(tag)
        f.write(ciphertext)

    end_time = time.time()
    elapsed_time = end_time - start_time
    print(f"Encryption completed in {elapsed_time:.3f} seconds.")
    print(f"File size: {len(plaintext)} bytes -> {len(ciphertext) + 51} bytes (encrypted)")

    return


def decrypt_file(username, password, infile, outfile):
    print(f"Decrypting file: {infile}")
    print(f"Output file: {outfile}")

    with open(infile, "rb") as f:
        raw_data = f.read()

    if len(raw_data) < 7 + 16 + 12 + 16:
        print("Ciphertext too short or corrupt.")
        return

    header = raw_data[0:7]
    if header != b"AES-GCM":
        print("Unsupported or corrupt file format.")
        return

    salt = raw_data[7:23]
    nonce = raw_data[23:35]
    tag = raw_data[35:51]
    ciphertext = raw_data[51:]

    # Derive key
    key = PBKDF2(password, salt, dkLen=32, count=600_000, hmac_hash_module=SHA256)

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

    # Re apply the AAD (username)
    aad = username.encode("utf-8")
    cipher.update(aad)

    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError:
        print(
            "Authentication failed. Wrong password, username (AAD), or corrupted data."
        )
        return

    with open(outfile, "wb") as f:
        f.write(plaintext)


def verify_user(username, password, users_file="data/sample_users.json"):
    with open(users_file, "r") as f:
        users = json.load(f)

    if username not in users:
        print(f"User '{username}' not found.")
        return False

    user_data = users[username]
    hash = user_data["pwd_hash_hex"]
    salt_hex = user_data["pwd_salt_hex"]
    iterations = user_data["pwd_iterations"]

    # Convert salt from hex to bytes
    salt = bytes.fromhex(salt_hex)

    # Derive key using the same parameters as stored
    key = PBKDF2(password, salt, dkLen=32, count=iterations, hmac_hash_module=SHA256)

    if key.hex().lower() == hash.lower():
        print(f"User '{username}' verified.")
        return True
    else:
        print(f"User '{username}' not verified.")
        return False


def main():
    parser = create_parser()
    args = parser.parse_args()

    if args.command == "check-password":
        print(f"Checking password: {args.password}")
        password_meter(args.password)
    elif args.command == "create-user":
        create_user(args.username, args.password)
    elif args.command == "build-bloom":
        build_bloom(args.blacklist, args.out)
    elif args.command == "check-bloom":
        check_bloom(args.bloom, args.password)
    elif args.command == "simulate-crack":
        simulate_crack(args.dict)
    elif args.command == "encrypt-file":
        encrypt_file(args.username, args.password, args.infile, args.outfile)
    elif args.command == "decrypt-file":
        decrypt_file(args.username, args.password, args.infile, args.outfile)
    elif args.command == "verify-user":
        verify_user(args.username, args.password, args.users_file)


if __name__ == "__main__":
    main()
