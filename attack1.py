import hashlib
import time


class HashCracker:
    def _init_(self, dictionary_file, target_files):
        self.dictionary_file = dictionary_file
        self.target_files = target_files
        self.dictionary = []
        self.target_hashes = {}

    def load_dictionary(self):
        with open(self.dictionary_file, 'r', encoding='utf-8', errors='ignore') as file:
            self.dictionary = [line.strip() for line in file]

    def load_target_hashes(self, algorithm):
        target_file = self.target_files.get(algorithm)
        with open(target_file, 'r') as file:
            self.target_hashes[algorithm] = set(line.strip() for line in file)

    def hash_password(self, password, algorithm):
        if algorithm == 'md5':
            return hashlib.md5(password.encode()).hexdigest()
        elif algorithm == 'sha1':
            return hashlib.sha1(password.encode()).hexdigest()
        elif algorithm == 'sha256':
            return hashlib.sha256(password.encode()).hexdigest()

    def crack_hashes(self, algorithm):
        cracked = []
        start_time = time.time()

        for password in self.dictionary:
            generated_hash = self.hash_password(password, algorithm)
            if generated_hash in self.target_hashes.get(algorithm, set()):
                cracked.append((password, generated_hash))

        end_time = time.time()
        cracking_time = end_time - start_time
        return cracked, cracking_time

    def save_results(self, algorithm, cracked, cracking_time):
        output_file = f"cracked_{algorithm}.txt"
        with open(output_file, 'w') as file:
            for password, hash_value in cracked:
                file.write(f"{password}:{hash_value}\n")

        time_file = f"time_analysis_{algorithm}.txt"
        with open(time_file, 'w') as file:
            file.write(f"{algorithm.upper()} cracking time: {
                       cracking_time:.2f} seconds\n")

    def run(self):
        self.load_dictionary()

        for algorithm in self.target_files:
            self.load_target_hashes(algorithm)
            cracked, cracking_time = self.crack_hashes(algorithm)
            print(f"Cracked {len(cracked)} {algorithm.upper()
                                            } hashes in {cracking_time:.2f} seconds.")
            self.save_results(algorithm, cracked, cracking_time)


def main():
    dictionary_file = 'dictionary/xato-net-10-million-passwords.txt'
    target_files = {
        'md5': 'md5_hashes.txt',
        'sha1': 'sha1_hashes.txt',
        'sha256': 'sha256_hashes.txt'
    }

    cracker = HashCracker(dictionary_file, target_files)
    cracker.run()


if __name__ == '_main_':
    main()
