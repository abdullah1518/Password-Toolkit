import json
import os
import re
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from rbloom import Bloom
import math
import argparse


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

    print(
        f"Your password has {entropy:.3f} bits of entropy, your rating is: {rating}. Suggestions: {suggestion}"
    )


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


def create_user(username, password, iterations=10**7):
    print(f"Creating user: {username}")
    salt = get_random_bytes(16)
    key = PBKDF2(password, salt, dkLen=32, count=iterations, hmac_hash_module=SHA256)

    user_data = {
        "username": username,
        "pwd_salt_hex": salt.hex(),
        "pwd_hash_hex": key.hex(),
        "pwd_iterations" : iterations
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
    bloom_filter = Bloom(100_000, 0.01, hash_func=hash_func) # 100,000 items expected, false positive rate of 0.01
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
    bloom_filter = Bloom.load(bloom_file, hash_func=hash_func)
    if password in bloom_filter:
        print(f"Password '{password}' is in the bloom filter.")
    else:
        print(f"Password '{password}' is not in the bloom filter.")
    return password in bloom_filter



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



if __name__ == "__main__":
    main()
