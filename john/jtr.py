import os
import glob

in_files = glob.glob('john/*.john')
print(in_files)
directories = ["archive", "results"]

def check_and_create_directories():
        for directory_path in directories:
            # Check if the directory exists
            if not os.path.exists(directory_path):
                print(f"Directory '{directory_path}' does not exist. Creating it now.")
                os.makedirs(directory_path)  # Create the directory (and any necessary parent directories)
            else:
                print(f"Directory '{directory_path}' already exists.")

def bf():
    for john_file in in_files:
        if john_file.contains('eapol'):
            jtr_format = 'wpapsk'
        elif john_file.contains('pmkid'):
            jtr_format = 'wpapsk-pmk'
        else:
            print('Invalid .john file.')
            return False

        print(f"\nRunning John the Ripper with format {jtr_format}...")
        os.system(f"john --format={jtr_format} --incremental {john_file}")

        output_file = john_file.replace(".john", "_cracked.txt")
        os.system(f"john --show --format={jtr_format} {john_file} > results/{output_file}")
        print(f'Storing results in results/{output_file}')
        os.system(f'cat results/{output_file}')

def main():
    check_and_create_directories()

    print("Running cyclic JTR Brute Force...")
    bf()


if __name__ == "__main__":
    main()