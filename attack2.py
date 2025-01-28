import hashlib
import time


def load_dictionary(file_path):
    with open(file_path, 'r') as file:
        return [line.strip() for line in file]


def load_salted_hashes(file_path):
    salted_hashes = []
    with open(file_path, 'r') as file:
        for line in file:
            line = line.strip()
            if ':' in line:
                salt, hash_val = line.split(':', 1)
                salted_hashes.append((salt, hash_val))
    return salted_hashes


def hash_password(password, salt, algorithm):
    combined = password + salt
    if algorithm == 'md5':
        return hashlib.md5(combined.encode()).hexdigest()
    elif algorithm == 'sha1':
        return hashlib.sha1(combined.encode()).hexdigest()
    elif algorithm == 'sha256':
        return hashlib.sha256(combined.encode()).hexdigest()


def crack_salted_hashes(dictionary, salted_hashes, algorithm):
    cracked = []
    start_time = time.time()
    for salt, target_hash in salted_hashes:
        for password in dictionary:
            generated_hash = hash_password(password, salt, algorithm)
            if generated_hash == target_hash:
                cracked.append((password, salt, target_hash))

    end_time = time.time()
    cracking_time = end_time - start_time
    return cracked, cracking_time


def save_cracked_passwords(cracked, output_file):
    with open(output_file, 'w') as file:
        for password, salt, hash_val in cracked:
            file.write(f"{password}:{salt}:{hash_val}\n")


def main():
    dictionary_file = 'dictionary/dictionary.txt'
    target_files = {
        'md5': 'md5_salted_hashes.txt',
        'sha1': 'sha1_salted_hashes.txt',
        'sha256': 'sha256_salted_hashes.txt'
    }

    for algorithm, target_file in target_files.items():

        dictionary = load_dictionary(dictionary_file)
        salted_hashes = load_salted_hashes(target_file)
        cracked, cracking_time = crack_salted_hashes(
            dictionary, salted_hashes, algorithm)

        print(f"Cracked {len(cracked)} {algorithm.upper()
                                        } salted hashes in {cracking_time:.2f} seconds.")
        output_file = f"salted_cracked_{algorithm}.txt"
        save_cracked_passwords(cracked, output_file)


if __name__ == '__main__':
    main()
