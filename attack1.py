import hashlib
import time


def load_dictionary(dictionary_file):
    with open(dictionary_file) as file:
        return [line.strip() for line in file]


def load_source_hashes(source_hash):
    with open(source_hash) as file:
        return [line.strip() for line in file]


def hash_password(password, algorithm):
    if algorithm == 'md5':
        return hashlib.md5(password.encode()).hexdigest()
    elif algorithm == 'sha1':
        return hashlib.sha1(password.encode()).hexdigest()
    elif algorithm == 'sha256':
        return hashlib.sha256(password.encode()).hexdigest()


def crack_hashes(dictionary, source_hashes, algorithm):
    cracked = []
    start_time = time.time()

    for password in dictionary:
        generated_hash = hash_password(password, algorithm)
        if generated_hash in source_hashes:
            cracked.append((password, generated_hash))

    end_time = time.time()
    return cracked, end_time - start_time


def save_results(algorithm, cracked, cracking_time):
    output_file = "cracked_" + algorithm + ".txt"
    with open(output_file, 'w') as file:
        for password, hash_value in cracked:
            file.write(password + ":" + hash_value + "\n")


def main():
    dictionary_file = 'dictionary/dictionary.txt'
    source_hash_files = {
        'md5': 'md5_hashes.txt',
        'sha1': 'sha1_hashes.txt',
        'sha256': 'sha256_hashes.txt'
    }

    dictionary = load_dictionary(dictionary_file)

    for algorithm, source_hash in source_hash_files.items():
        source_hashes = load_source_hashes(source_hash)
        cracked, cracking_time = crack_hashes(
            dictionary, source_hashes, algorithm)
        print(f"Cracked {len(cracked)} {algorithm.upper()
                                        } hashes in {cracking_time:.2f} seconds.")
        save_results(algorithm, cracked, cracking_time)


if __name__ == '__main__':
    main()
