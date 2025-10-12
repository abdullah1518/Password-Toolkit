import Crypto as crypt
import math

def password_meter():
    pwd = input("Enter password: ")
    ratings =["weak", "fair", "good", "strong"]
    rating = ""
    length = len(pwd)
    range = 0
    
    specialChars = r"""!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~"""
    hasDigit = any(char.isdigit() for char in pwd)
    hasUpper = any(char.isupper() for char in pwd)
    hasLower = any(char.islower() for char in pwd)
    hasSpe = any(char in specialChars for char in pwd)

    if hasUpper: range += 26    # 26 uppercase characters
    if hasLower: range += 26    # 26 lowercase characters
    if hasDigit: range += 10    # 10 digits
    if hasSpe: range += len(specialChars)   # custom range depending on the list

    entropy = length * math.log2(range)     # using formula E = L*log2(R)
    if entropy < 30:
        rating = ratings[0]
    elif entropy < 40:
        rating = ratings[1]
    elif entropy < 60:
        rating = ratings[2]
    else:
        rating = ratings[3]


    print(f"Your password has {entropy:.3f} bits of entropy, your rating is: {rating}")

    #TODO




def main():
    while(True):
        password_meter()

if __name__ == "__main__":
    main()