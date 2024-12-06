def manual_hash(input_string: str, salt: str = "") -> int:
    """
    Manual hash function without libraries, featuring salt, improved mixing, 
    and a 64-bit output.
    
    :param input_string: The input string to hash.
    :param salt: Optional salt to add uniqueness to the hash.
    :return: The resulting hash as a 64-bit integer.
    """
    # Add the salt to the input string
    input_with_salt = salt + input_string

    # Start with a large prime number as the initial hash value
    hash_value = 0xABCDEF1234567890

    # Iterate over each character in the input string
    for i, char in enumerate(input_with_salt):
        # Use the character's ASCII value
        char_code = ord(char)

        # Mix the hash value with bitwise operations
        hash_value ^= (char_code + i) * 0x5BD1E995  # XOR and multiply by a large prime
        hash_value = (hash_value << 7 | hash_value >> 57)  # Rotate left 7 bits
        hash_value += char_code * (i + 1)  # Add a weighted value

        # Ensure the hash remains within 64-bit
        hash_value &= 0xFFFFFFFFFFFFFFFF

    # Return the final 64-bit hash value
    return hash_value

# Example Usage
if __name__ == "__main__":
    test_string = "hello world"
    print("Hash with default salt:")
    print(manual_hash(test_string))
    
    print("\nHash with custom salt:")
    print(manual_hash(test_string, salt="my_custom_salt"))
