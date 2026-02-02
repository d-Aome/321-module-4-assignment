import sys
from hashlib import sha256


def text_to_digest(input):
    hasher = sha256(input)
    # return digest in btye format
    return hasher.digest()


def hamming_distance(str1, str2):
    count = 0
    for char1, char2 in zip(str1, str2):
        if char1 != char2:
            count += 1

    return count


def find_collision(bit_size):
    hashes_seen = {}

    bitmask = (1 << bit_size) - 1

    counter = 0
    while True:
        input_str = f"{counter}"
        full_hash = sha256(input_str.encode()).digest()

        hash_int = int.from_bytes(full_hash[:8], byteorder="big")

        truncated_hash = hash_int & bitmask
        if truncated_hash in hashes_seen:
            print(f"Collision String: {input_str}")
            print(f"Dictionary String: {hashes_seen[truncated_hash]}")
            print(f"Collision String: {input_str}")
            break
        else:
            counter += 1
            hashes_seen[truncated_hash] = input_str

    return 0


def main():
    if len(sys.argv) > 1:
        try:
            bit_size = int(sys.argv[1])
            find_collision(bit_size)
        except ValueError:
            print("Provide an integer value please")
    else:
        print("Provide an arguement")


print()
if __name__ == "__main__":
    main()
