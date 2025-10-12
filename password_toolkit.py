import re
import Crypto
import math
import argparse

def create_parser():
    parser = argparse.ArgumentParser()
    subparser = parser.add_subparsers(title='Available Commands', dest='command')

    # Check password
    parser_check = subparser.add_parser('check-password', help='Checks the strength of a given password.')
    parser_check.add_argument(
    '--password', '-p',
    required=True,
    help='The password string to check.' )

    return parser

def password_meter(password):
    ratings =["weak", "fair", "good", "strong"]
    rating = ""
    repeat = False
    common = False
    sequence = False
    year = False
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
        
    

    print(f"Your password has {entropy:.3f} bits of entropy, your rating is: {rating}. Suggestions: {suggestion}")

def check_simple_sequence(password, min_length=3):
    n = len(password)
    
    for i in range(n - min_length + 1):
        substring = password[i : i + min_length]
        
        # Check for ascending sequence (e.g., '1', '2', '3' or 'a', 'b', 'c')
        is_ascending = all(
            ord(substring[j]) == ord(substring[j-1]) + 1
            for j in range(1, len(substring))
        )
        
        # Check for descending sequence (e.g., '3', '2', '1' or 'c', 'b', 'a')
        is_descending = all(
            ord(substring[j]) == ord(substring[j-1]) - 1
            for j in range(1, len(substring))
        )

        if is_ascending or is_descending:
            return True, substring # Sequence found
            
    return False

def check_entropy(password):
    length = len(password)
    range = 0

    specialChars = r"""!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~"""
    hasDigit = any(char.isdigit() for char in password)
    hasUpper = any(char.isupper() for char in password)
    hasLower = any(char.islower() for char in password)
    hasSpe = any(char in specialChars for char in password)

    if hasUpper: range += 26    # 26 uppercase characters
    if hasLower: range += 26    # 26 lowercase characters
    if hasDigit: range += 10    # 10 digits
    if hasSpe: range += len(specialChars)   # custom range depending on the list

    return length * math.log2(range)     # using formula E = L*log2(R)


def check_common_substring(password):
    QWERTY_SEQUENCES = [
    "qwerty", "yuiop", "asdfg", "ghjkl", "zxcvb", "bnm",
    "trewq", "poiuy", "lkjhg", "mnbvc", 
    "qaz", "wsx", "edc", "rfv", "tgb",  
    "12345", "54321", "67890", "09876" 
    ]
    password_lower = password.lower()
    
    for sequence in QWERTY_SEQUENCES:
        if sequence in password_lower:
            return True, sequence # Sequence found
            
    return False

def main():
    parser = create_parser()
    args = parser.parse_args()

    if args.command == 'check-password':
        print(f"Checking password: {args.password}")
        password_meter(args.password)

if __name__ == "__main__":
    main()