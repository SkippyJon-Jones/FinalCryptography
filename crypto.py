import random
import math

# Caesar Cipher
# Arguments: string, integer
# Returns: string


def encrypt_caesar(plaintext, offset):
    ascii_min = 64
    ascii_max = 91
    alphabet_shift = 26
    encrypt = ""

    for letter in plaintext:
        current = ord(letter)

# Checks if the character is a valid one to shift
        if current > ascii_min and current < ascii_max:
            char = ord(letter) + offset
# Checks if the shift goes over the ascii value for z
            if (char) > ascii_max - 1:
                char = char - alphabet_shift
            current = char
        encrypt = encrypt + chr(current)

    return encrypt

# Arguments: string, integer
# Returns: string


def decrypt_caesar(ciphertext, offset):
    ascii_min = 64
    ascii_max = 91
    alphabet_shift = 26
    decrypt = ""

    for letter in ciphertext:
        current = ord(letter)
        if current > ascii_min and current < ascii_max:
            char = ord(letter) - offset
            if (char) < ascii_min + 1:
                char = char + alphabet_shift
            current = char
        decrypt = decrypt + chr(current)
    return decrypt

# Vigenere Cipher
# Arguments: string, string
# Returns: string


def encrypt_vigenere(plaintext, keyword):
    ascii_max = 90
    ascii_min = 65
    alphabet_shift = 26
    
    encrypt = ""
    actualkeyword = ""
    current_index = 0

# Creates a new string that is the keyword repeating itself
# to become an equal length to the plain text #
    for char in plaintext:
        actualkeyword = actualkeyword + keyword[current_index]
# Resets the indices that is looping through the original keyword
        if(current_index == len(keyword) - 1):
            current_index = - 1
        current_index = current_index + 1

    current_index = 0

    for char in plaintext:
        letter = ord(char) + ord(actualkeyword[current_index]) - ascii_min
# Checks to see if the character needs to loop around
# to beginning of alphabet
        if(letter > ascii_max):
            letter = letter - alphabet_shift
        encrypt = encrypt + chr(letter)
        current_index = current_index + 1

    return encrypt

# Arguments: string, string
# Returns: string


def decrypt_vigenere(ciphertext, keyword):
    decrypt = ""
    actualkeyword = ""
    cipher_index = 0
    ascii_min = 65
    alphabet_shift = 26

# Creates a new string that is the keyword repeating itself
# to become an equal length to the plain text
    for char in ciphertext:
        actualkeyword = actualkeyword + keyword[cipher_index]
        
        # Resets the indices that is looping through the original keyword
        if(cipher_index == len(keyword) - 1):
            cipher_index = - 1
        cipher_index = cipher_index + 1

    keyword_index = 0

    for char in ciphertext:
        letter = ord(char) - ord(actualkeyword[keyword_index]) + ascii_min
# Checks to see if the character needs to loop around 
# to end of alphabet
        if(letter < ascii_min):
            letter = letter + alphabet_shift
        decrypt = decrypt + chr(letter)
        keyword_index = keyword_index + 1

    return decrypt

# Merkle-Hellman Knapsack Cryptosystem
# Arguments: integer
# Returns: tuple (W, Q, R) - W a length-n tuple of integers,
# Q and R both integers


def generate_private_key(n=8):
    w = [1]
    current_index = 1
    total = 1
# Creates a random superincreasing sequence that starts at 1
    while current_index < n:
        w.append(random.randint(total+1, 2*total))
        total = total + w[current_index]
        current_index = current_index + 1

    W = tuple(w)

# Creates a Q value that is larger than the largest element in W
    Q = random.randint(total+1, 2*total)

# Finds an R value where its greatest common denominator with Q is 1
    while 1 == 1:
        R = random.randint(2, Q-1)
        if math.gcd(R, Q) == 1:
            break

    return (W, Q, R)

# Arguments: tuple (W, Q, R) - W a length-n tuple of integers,
# Q and R both integers
# Returns: B - a length-n tuple of integers


def create_public_key(private_key):
    b = []
    W, Q, R = private_key
# Modifies W, the list of superincreasing values, to creat a public key
    for W_i in W:
        b.append((R * W_i) % Q)

    B = tuple(b)

    return B

# Arguments: string, tuple B
# Returns: list of integers


def encrypt_mhkc(plaintext, public_key):
    listofCs = []

    for letter in plaintext:
        # Converts each char in plaintext into its binary value
        # using 8 digits
        asciiValue = ord(letter)
        binaryvalue = '{0:08b}'.format(asciiValue)
        M = []

# Converts it from the binary value into a list of
# the binary representation
        for num in binaryvalue:
            M.append(num)

        index_public_key = 0
        C = 0
# Creates a C value that is a representation
# of the individual character
        for M_i in M:
            C = C + (int(M_i) * public_key[index_public_key])
            index_public_key = index_public_key + 1

# Add each C value to the list
        listofCs.append(C)

    return listofCs

# Arguments: list of integers, private key (W, Q, R) with W a tuple.
# Returns: bytearray or str of plaintext


def decrypt_mhkc(ciphertext, private_key):
    decryptchars = []
    W, Q, R = private_key

# Generates an S value that satisfies the equation below
    for S in range(2, Q):
        if ((S * R) % Q == 1):
            break
    C2 = []

# Creates a modified list of values from the ciphertext
    for C in ciphertext:
        C2.append((C * S) % Q)

    for Cval in C2:
        indicesInOriginal = []
# Starts index at top of the list
        SIL_index = len(W) - 1
# Loops through the superincreasing list comparing its
# values with the C value
        while SIL_index > -1:
            # If its larger then go onto the next, smaller integer
            if(W[SIL_index] > Cval):
                SIL_index = SIL_index - 1
            else:  # If smaler, subtract it from the C value
                Cval = Cval - W[SIL_index]
# The index of the super increasing starts from the top so
# to get the index where there is a 1 in the binary representation
# have to subtract the index from the total number of indices
                indicesInOriginal.append(len(W) - SIL_index)
                SIL_index = SIL_index - 1
# Once the C value is 0 there are no more binary values to be added
            if Cval == 0:
                break
        asciival = 0
# Loops through where the indices are in the binary value
# of the original string and computes its asciivalue
        for index in indicesInOriginal:
            asciival = asciival + (2 ** (index - 1))
# Converts the asciival to a char and adds
# it to the list of the original text
        decryptchars.append(chr(asciival))

    return decryptchars

# Arguments: List
# Returns: String


def list_to_string(list):
    string = ""
    for letter in list:
        string = string + letter
    return string

# Arguments: String, or list
# Returns: True or False


def check_if_equal(input, compare):
    if input == compare:
        return True
    else:
        return False


def main():
    # Caeser Test
    print("Caeser Test:")
    Ctest_string = "WITH TWO SPACES"
    Cfinal_string = "ZLWK WZR VSDFHV"
    Cshift = 3
    caeser_E = encrypt_caesar(Ctest_string, Cshift)
    caeser_D = decrypt_caesar(caeser_E, Cshift)
    print(caeser_E)
    print(check_if_equal(caeser_E, Cfinal_string))
    print(caeser_D)
    print(check_if_equal(caeser_D, Ctest_string))
    print(" ")

    # Vingere Test
    print("Vingere Test:")
    Vplaintext = "SHORTERKEY"
    Vencrypted = "PFNQRDOIDX"
    Vkey = "XYZZYZ"
    vigenere_E = encrypt_vigenere(Vplaintext, Vkey)
    vigenere_D = decrypt_vigenere(vigenere_E, Vkey)
    print(vigenere_E)
    print(check_if_equal(vigenere_E, Vencrypted))
    print(vigenere_D)
    print(check_if_equal(vigenere_D, Vplaintext))
    print(" ")

    # MHKC Test
    print(":")
    private_key = ((5, 10, 28, 59, 144, 309, 688, 2413), 5575, 2)
    public_key = (10, 20, 56, 118, 288, 618, 1376, 4826)
    message = ""
    encrypted = []
    mhkc_E = encrypt_mhkc(message, public_key)
    mhkc_D = decrypt_mhkc(mhkc_E, private_key)
    print(mhkc_E)
    print(check_if_equal(mhkc_E, encrypted))
    print(list_to_string(mhkc_D))
    print(check_if_equal(list_to_string(mhkc_D), message))

if __name__ == "__main__":
    main()
