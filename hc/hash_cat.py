import os
import subprocess
import shutil
import glob
import urllib.request


# Function to find the .22000 file in the current directory
def find_22000_file():
    files = glob.glob("*.22000")
    if files:
        return files[0]
    return None

# Function to check if a hash is already cracked (exists in the potfile)
def is_hash_cracked(hash_value, potfile_path="hashcat.potfile"):
    try:
        with open(potfile_path, "r") as potfile:
            for line in potfile:
                if hash_value in line:
                    return True
    except FileNotFoundError:
        print(f"Potfile {potfile_path} not found.")
    return False

# Run Hashcat with the specified command
def run_hashcat(command):
    print(f"Running command: {command}")
    subprocess.run(command, shell=True)

# Function to remove the filtered.22000 file if it exists
def remove_filtered_file(file_path):
    if os.path.exists(file_path):
        os.remove(file_path)
        print(f"✅ Removed {file_path}")
    else:
        print(f"❌ No filtered file found to remove.")

def find_file(file_name, url):
    # Check if the file exists
    if not os.path.isfile(file_name):
        print(f"{file_name} not found. Downloading...")
        
        # Download the file
        urllib.request.urlretrieve(url, file_name)
        print(f"{file_name} downloaded successfully!")
    else:
        print(f"{file_name} already exists.")

# Main function to process the file
def main():
    potfile_path = "hashcat.potfile"
    archive_dir = "archive"
    text_file = "rockyou.txt"
    text_url = "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt"

    # Ensure the archive directory exists
    if not os.path.exists(archive_dir):
        os.makedirs(archive_dir)

    # Find the .22000 file
    file_22000 = find_22000_file()
    if not file_22000:
        print("❌ No .22000 file found in the directory.")
        return

    print(f"📂 Found .22000 file: {file_22000}")

    find_file(text_file,text_url)

    # Define Hashcat attack commands increasing in complexity
    commands = [
        # Estimated Time: ~10 seconds
        # Hybrid attack (wordlist + 3-symbol suffix, e.g., !@#)
        f"hashcat -m 22000 -a 6 {file_22000} {text_file} !@#",

        # Estimated Time: ~3 minutes
        # Brute-force attack (digits only, exactly 8 digits)
        f"hashcat -m 22000 -a 3 {file_22000} ?d?d?d?d?d?d?d?d",

        # Estimated Time: ~5–30 minutes
        # Straight attack (wordlist + simple rule)
        f"hashcat -m 22000 -a 0 {file_22000} {text_file} -r rules/best64.rule",

        # Estimated Time: ~5–30 minutes
        # Combinator attack (combine two different wordlists to reach 8+ characters)
        f"hashcat -m 22000 -a 1 {file_22000} {text_file} clearlist.txt",

        # # Estimated Time: ~30 minutes – 2 hours
        # # Straight attack with aggressive rule set
        # f"hashcat -m 22000 -a 0 {file_22000} {text_file} -r rules/dive.rule",

        # Estimated Time: ~4.3 hours
        # Targeted mask attack (e.g., capital + lowercase + digits + special) - exactly 8 chars
        f"hashcat -m 22000 -a 3 {file_22000} ?u?l?l?l?l?d?d?s",

        # # Estimated Time: ~3.1 days
        # # Dictionary + smart pattern mask (e.g., base word + digits)
        # f"hashcat -m 22000 -a 9 {file_22000} {text_file} ?d?d?d?d",

        # # Estimated Time: ~3.1 days
        # # Hybrid attack (wordlist + 4-digit suffix to reach 8+ chars)
        # f"hashcat -m 22000 -a 6 {file_22000} {text_file} ?d?d?d?d",

        # # Estimated Time: ~4.6 days
        # # Brute-force attack (all lowercase, exactly 8 characters)
        # f"hashcat -m 22000 -a 3 {file_22000} ?l?l?l?l?l?l?l?l",

        # # Estimated Time: ~10–12 days
        # # Mask + Rule combo (mask meets 8-char min, rules mutate)
        # f"hashcat -m 22000 -a 7 {file_22000} ?l?l?l?l?l?l?l?l -r rules/best64.rule",

        # # Estimated Time: ~105 days
        # # Custom charset brute-force (8 characters using upper, lower, digits, and limited specials)
        # f"hashcat -m 22000 -a 3 {file_22000} -1 ?l?u?d!@#$%&*? ?1?1?1?1?1?1?1?1",

        # # Estimated Time: ~180 days
        # # Incremental brute-force from 8 to 10 characters (only mixed case and digits)
        # f"hashcat -m 22000 -a 3 {file_22000} -i --increment-min=8 --increment-max=10 ?l?u?d",
    ]




    # Run each command only if the hashes are not already cracked
    # Load all hashes
    with open(file_22000, 'r') as file:
        hash_lines = file.readlines()

    # Extract hash values from each line (adjust if needed)
    hashes = [line.split("*")[2] for line in hash_lines]

    # Loop through commands once
    for command in commands:
        # Check if there are any uncracked hashes
        uncracked = [h for h in hashes if not is_hash_cracked(h, potfile_path)]

        if uncracked:
            print(f"🔁 Running: {command}")
            run_hashcat(command)
        else:
            print("✅ All hashes already cracked. Skipping this command.")

        
    # After all hashcat commands, move the original .22000 file to the archive folder
    shutil.move(file_22000, os.path.join(archive_dir, file_22000))
    print(f"📁 File {file_22000} moved to archive.")

    # Optionally remove filtered.22000 file if it exists
    remove_filtered_file("filtered.22000")

if __name__ == "__main__":
    main()

