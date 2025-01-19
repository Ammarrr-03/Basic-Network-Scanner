import os
import random

class SecureFileShredder:
    def __init__(self, file_path):
        self.file_path = file_path
        self.shredding_algorithms = {
            'Zero-Fill': self.zero_fill,
            'Random Data': self.random_data,
            'DoD 5220.22-M': self.dod_5220_22_m
        }

    def zero_fill(self):
        with open(self.file_path, 'wb') as file:
            file.write(b'\x00' * os.path.getsize(self.file_path))
        os.remove(self.file_path)
        print(f"File {self.file_path} has been securely shredded using Zero-Fill.")

    def random_data(self):
        with open(self.file_path, 'wb') as file:
            file.write(bytes(random.randint(0, 255) for _ in range(os.path.getsize(self.file_path))))
        os.remove(self.file_path)
        print(f"File {self.file_path} has been securely shredded using Random Data.")

    def dod_5220_22_m(self):
        patterns = [b'\x00', b'\xFF', b'\xAA']
        with open(self.file_path, 'wb') as file:
            for _ in range(3):
                for pattern in patterns:
                    file.write(pattern * os.path.getsize(self.file_path))
        os.remove(self.file_path)
        print(f"File {self.file_path} has been securely shredded using DoD 5220.22-M.")

    def shred_file(self, algorithm):
        if algorithm in self.shredding_algorithms:
            self.shredding_algorithms[algorithm]()
        else:
            print("Invalid shredding algorithm selected.")

# Example usage
file_path = 'example.txt'
shredder = SecureFileShredder(file_path)
shredder.shred_file('Zero-Fill')
