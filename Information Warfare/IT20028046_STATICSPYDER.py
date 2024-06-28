import math
import requests
import hashlib
import os
import pefile
import magic

print(r"""
███████ ████████  █████  ████████ ██  ██████ ███████ ██████  ██    ██ ██████  ███████ ██████      
██         ██    ██   ██    ██    ██ ██      ██      ██   ██  ██  ██  ██   ██ ██      ██   ██     
███████    ██    ███████    ██    ██ ██      ███████ ██████    ████   ██   ██ █████   ██████      
     ██    ██    ██   ██    ██    ██ ██           ██ ██         ██    ██   ██ ██      ██   ██     
███████    ██    ██   ██    ██    ██  ██████ ███████ ██         ██    ██████  ███████ ██   ██""")
print("\n****************************************************************")
print("\n* Copyright of Buddhika shehan, 2023                           *")
print("\n****************************************************************")


def show_menu():
    print("Select an option:")
    print("1. SET/CHANGE THE FILE PATH")
    print("2. HASH CALCULATOR")
    print("3. SHANNON ENTROPY CALCULATOR")
    print("4. FILE TYPE ANALYZER")
    print("5. PE FILE HEADER ANALYZER")
    print("6. STRINGS ANALYZER")
    print("7. CHECK FILE ON VIRUSTOTAL")
    print("\nType 'exit' to quit\n")


def is_valid_file_path(file_path):
    return os.path.exists(file_path)


# change file path
def set_file_path():
    global file_path
    global user
    user_input = input("Enter the path to the file: ")
    file_path = user_input.replace("\\", "\\\\")
    if is_valid_file_path(user_input):
        print(f"The file path {user_input} is valid.")
        print("File path has set to :", user_input, "\n")
    else:
        print(f"The file path {user_input} is not valid or does not exist.")


# hash calculation function
def calculate_hashes(file_path):
    md5_hash = hashlib.md5()
    sha1_hash = hashlib.sha1()
    sha256_hash = hashlib.sha256()
    sha512_hash = hashlib.sha512()

    with open(file_path, "rb") as file:
        while chunk := file.read(8192):
            md5_hash.update(chunk)
            sha1_hash.update(chunk)
            sha256_hash.update(chunk)
            sha512_hash.update(chunk)

    md5_digest = md5_hash.hexdigest()
    sha1_digest = sha1_hash.hexdigest()
    sha256_digest = sha256_hash.hexdigest()
    sha512_digest = sha512_hash.hexdigest()

    return md5_digest, sha1_digest, sha256_digest, sha512_digest


def print_hashes(md5_result, sha1_result, sha256_result, sha512_result):
    print(f"MD5:      {md5_result}")
    print(f"SHA-1:    {sha1_result}")
    print(f"SHA-256:  {sha256_result}")
    print(f"SHA-512:  {sha512_result}")
    print("\n")


def shannon_entropy(data):
    # 256 different possible values
    possible = dict(((chr(x), 0) for x in range(0, 256)))

    for byte in data:
        possible[chr(byte)] += 1

    data_len = len(data)
    entropy = 0.0

    # compute
    for i in possible:
        if possible[i] == 0:
            continue

        p = float(possible[i] / data_len)
        entropy -= p * math.log(p, 2)
    return entropy


def calculate_entropy(file_path):
    with open(file_path, 'rb') as f:
        data = f.read()
        if data:
            entropy = shannon_entropy(data)
            print(f"Shannon Entropy of {file_path}: {entropy}", "\n")


# file type analyzer
def identify_file_type_using_magic(file_path):
    """Identifies the file type using the magic library.

    Args:
        file_path: The path to the file.

    Returns:
        A string containing the file type.
    """
    mime = magic.Magic()
    file_type = mime.from_file(file_path)
    return file_type


def filetype():
    """Your existing main function."""
    # Your existing code here...
    original_file_type = identify_file_type_using_magic(file_path)
    print(f"The file type is: {original_file_type}")


# pe file analyzer
def analyze_pe_file(file_path):
    try:
        # Open the PE file
        pe = pefile.PE(file_path)

        # Display basic information
        print(f"File: {file_path}")

        # Check for the magic number
        if pe.DOS_HEADER.e_magic == 0x4D5A:
            print("Magic Number (Signature): MZ")
        else:
            print(f"Magic Number (Signature): {hex(pe.DOS_HEADER.e_magic)}")

        print(f"Image Base: 0x{pe.OPTIONAL_HEADER.ImageBase:08X}")
        print(f"Entry Point: 0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:08X}")

        # Display section information
        print("\nSection Headers:")
        for section in pe.sections:
            if section.Name and section.Name != b'\x00':
                print("  {} - Virtual Size: {:08X}".format(section.Name.decode('utf-8').rstrip('\x00'),
                                                           section.Misc_VirtualSize))
            else:
                print(f"  Unknown Section - Virtual Size: {section.Misc_VirtualSize:08X}")

        # Display imported functions
        print("\nImported Functions:")
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            if entry.dll and entry.dll != b'\x00':
                print(f"  {entry.dll.decode('utf-8')}")
                for func in entry.imports:
                    if func.name and func.name != b'\x00':
                        print(f"    {func.name.decode('utf-8')}")

    except Exception as e:
        print(f"Error: {e}")


# strings analysis
def extract_strings(file_path, min_length=4):
    with open(file_path, 'rb') as file:
        content = file.read()

    strings = []
    current_string = ""

    for byte in content:
        if 0x20 <= byte <= 0x7E or byte == 0x0A or byte == 0x0D:
            # ASCII printable characters or newline/return
            current_string += chr(byte)
        else:
            if len(current_string) >= min_length:
                strings.append(current_string)
            current_string = ""

    # Add the last string if it meets the minimum length
    if len(current_string) >= min_length:
        strings.append(current_string)

    return strings


def analyze_strings(file_path, min_length=4):
    strings = extract_strings(file_path, min_length)

    print(f"Strings in {file_path} (minimum length: {min_length}):")
    for i, string in enumerate(strings, start=1):
        print(f"{i}. {string}")


# virus total check


# Replace '' with your actual VirusTotal API key
API_KEY = ''
API_URL = 'https://www.virustotal.com/vtapi/v2/file/report'


def check_file_hashVT(file_hash):
    params = {'apikey': API_KEY, 'resource': file_hash}
    response = requests.get(API_URL, params=params)

    if response.status_code == 200:
        result = response.json()
        if result['response_code'] == 1:
            positives = result['positives']
            total = result['total']
            scan_results = result['scans']

            print(f'File is detected as malicious by {positives} out of {total} antivirus vendors.')
            print('Details of antivirus vendors:')
            for vendor, result in scan_results.items():
                if result['detected']:
                    print(f'{vendor}: {result["result"]}')
        else:
            print('File not found on VirusTotal.')
    else:
        print('Error while connecting to VirusTotal.')


def check_VT():
    user_hash = md5_hash
    check_file_hashVT(user_hash)




# run toolkit>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

file_path = ""
md5_hash = 0


def run_toolkit():
    while True:
        show_menu()
        option = input("Option: ")
        print("\n")
        if option == 'exit':
            break
        elif option in ['1', '2', '3', '4', '5', '6', '7']:

            if option == '1':
                set_file_path()

            elif option == '2':
                md5_result, sha1_result, sha256_result, sha512_result = calculate_hashes(file_path)
                print_hashes(md5_result, sha1_result, sha256_result, sha512_result)

            elif option == '3':
                calculate_entropy(file_path)

            elif option == '4':
                filetype()
                print("\n")

            elif option == '5':
                analyze_pe_file(file_path)
                print("\n")

            elif option == '6':
                analyze_strings(file_path)
                print("\n")

            elif option == '7':
                check_VT()
                print("\n")
        else:
            print("Invalid option")


if __name__ == '__main__':
    print("\nWelcome to the malware static analysis toolkit!\n")
    run_toolkit()