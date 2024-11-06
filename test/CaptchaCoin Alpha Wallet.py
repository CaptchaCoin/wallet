try:
    import time
    import os
    import random
    import getpass
    import hashlib
    import webbrowser
except:
    input("There was an error importing one or more of the following standard libraries: time, os, random, getpass, hashlib, webbrowser")
    exit()

try:
    from ecdsa import SigningKey, SECP256k1, VerifyingKey
except:
    input("There was an error importing the ecdsa library. Please install the ecdsa library and try again.")
    exit()

def main():
    global random_time
    random_time = hashlib.sha256(str(time.time()).encode("utf-8")).digest()
    print("CaptchaCoin Wallet Software - Alpha release")
    print("This version of the CaptchaCoin wallet software is for testing only.\nPlease only use it with very small quantities of Caps.\n")
    print("Wallets created using test software may not be supported in the future.")
    initial_prompt()

def time_randomness():
    global random_time
    time_now = hashlib.sha256(str(time.time()).encode("utf-8")).digest()
    random_time=[(time_now + random_time) % 256 for time_now, random_time in zip(time_now, random_time)]
    return random_time

def initial_prompt():
    time_randomness()
    print("Enter a command, or select one of the following options:\n[1] Create a wallet\n[2] Access a wallet and create a transaction\n[3] Verify a transaction\n")
    user_input = input("Please enter an option (1, 2 or 3): ")
    time_randomness()
    if user_input == "1":
        create_wallet_input()
    elif user_input == "2":
        access_wallet()
    elif user_input == "3":
        verify_transaction()
    else:
        run_command(user_input)

def run_command(user_input):
    # TODO - This will evaluate user input and execute the corresponding function
    user_input=input(">")
    run_command(user_input)

def create_wallet_input():
    time_randomness()
    print("\n\nWhat sort of wallet would you like to create?\n")
    print("[1] A randomly generated wallet. This will create a file on your computer containing all of the wallet information.\nIf you lose this file, you will lose the wallet and any funds.\n")
    print("[2] A passphrase wallet (brain wallet). You will enter a series of words as your seed.\nIf you forget the series of words, you will lose the wallet and any funds.\n")
    user_input = input("Please enter an option (1 or 2): ")
    time_randomness()
    if user_input == "1":
        create_wallet_random_input()
    elif user_input == "2":
        create_wallet_seed_input()
    else:
        print("Input not recognised. Please try again.")
        create_wallet_input()

def create_wallet_random_execute(file_name,password,user_random):
    random_time=bytearray(time_randomness())
    if len(password) > 0:
        hashed_password = hashlib.sha256(str(password).encode("utf-8")).digest()
    else:
        hashed_password = [0]*32
    if len(file_name) == 0:
        file_name="CaptchaCoin Wallet"
    # Hash inputs
    private_key_input = hashlib.sha256(user_random.encode("utf-8")+random_time+str(random.randrange(1000000000000)).encode("utf-8"))
    # A very small proportion of inputs are not valid for a private key. Keep hashing the input if necessary
    valid_key_found=0
    while valid_key_found==0:
        try:
            private_key = SigningKey.from_string(private_key_input.digest(), curve=SECP256k1, hashfunc=hashlib.sha256)
            valid_key_found=1
        except:
            private_key_input = hashlib.sha256(private_key_input.digest())
    address=(b"\x00\x00"+hashlib.sha256(private_key.verifying_key.to_string('compressed')).digest()).hex()
    if len(file_name)>0:
        save_wallet(private_key, file_name, hashed_password)
    global active_private_key
    active_private_key = private_key
    global active_address
    active_address=address
    return private_key

def create_wallet_random_input():
    time_randomness()
    print("\n\nYour wallet will be created using randomness from your computer, as well as user-generated randomness\n")
    sufficient_randomness0=0
    user_random = ""
    while sufficient_randomness0==0:
        if len(user_random) > 31:
            time_randomness()
            sufficient_randomness0 = 1
        else:
            time_randomness()
            user_random += getpass.getpass("Please randomly press buttons on your keyboard, then push the Enter key")
    print("")
    sufficient_randomness1=0
    while sufficient_randomness1==0:
        time_randomness()
        if len(user_random) > 63:
            sufficient_randomness1 = 1
        else:
            user_random += getpass.getpass("To add further randomness, please randomly press buttons on your keyboard, then push Enter")
    password_match=0
    print("You may protect your wallet with a password. This should NOT be the same as your passphrase. To continue without a password, leave the password field blank.")
    while password_match==0:
        userpass0 = getpass.getpass("Enter password")
        time_randomness()
        if len(userpass0) > 0:
            userpass1 = getpass.getpass("Enter password again")
            time_randomness()
            if userpass0 == userpass1:
                password_match=1
                print("Password accepted")
            else:
                print("Passwords didn't match")
        else:
            print("Your wallet will not be password protected")
            password_match=1
    file_name = input("Give your wallet file a name? (optional - default: CaptchaCoin Wallet)\n")
    file_name = file_name.strip()
    if len(file_name) == 0:
        file_name="CaptchaCoin Wallet"
    time_randomness()
    private_key=create_wallet_random_execute(file_name,userpass0,user_random)
    address=(b"\x00\x00"+hashlib.sha256(private_key.verifying_key.to_string('compressed')).digest()).hex()
    # Print address
    user_input = input("\nWhat you like to do next?\n[1] Mine Caps to this address\n[2] Back to the main menu\n[Any other key] Quit\n")
    print("\n\n")
    if user_input=="1":
        webbrowser.open('https://www.captchacoin.net/earn/login-user.php?' + address)
    elif user_input=="2":
        initial_prompt()
    else:
        exit()
    initial_prompt()

def create_wallet_seed_input():
    print("\n\nGenerate a wallet from a seed phrase. Only choose this option if you are confident you understand the requirements of doing so.\n")
    print("Your seed phrase is case-sensitive, and the placement of all spaces and other special characters must be identical when re-creating your wallet.")
    print("Would you like to view your pass phrase as you type it?\n[1] View as plain text\n[2] Do not show any user input")
    valid_input=0
    while valid_input==0:
        user_input = input("Please choose 1 or 2\n")
        if user_input=="1" or user_input =="2":
            valid_input=1
    valid_passphrase=0
    while valid_passphrase==0:
        if user_input=="1":
            passphrase0 = input("Please enter your passphrase:    ")
            passphrase1 = input("Please re-enter your passphrase: ")
            if passphrase0==passphrase1:
                valid_passphrase=1
            else:
                print("Your passphrases do not match.")
        else:
            passphrase0 = getpass.getpass("Please enter your passphrase:    ")
            passphrase1 = getpass.getpass("Please re-enter your passphrase: ")
            if passphrase0==passphrase1:
                valid_passphrase=1
            else:
                print("Your passphrases do not match.")
    private_key=create_wallet_seed_execute(passphrase0,0,"","")
    address=(b"\x00\x00"+hashlib.sha256(private_key.verifying_key.to_string('compressed')).digest()).hex()
    time.sleep(3)
    user_input = input("\nWhat you like to do next?\n[1] Mine Caps to this address\n[2] Save the wallet as a file.\n[3] Back to the main menu\n[Any other key] Quit\n")
    print("\n\n")
    if user_input=="1":
        webbrowser.open('https://www.captchacoin.net/earn/login-user.php?' + address)
    elif user_input=="2":
        save_wallet(private_key,"","")
    elif user_input=="3":
        initial_prompt()
    else:
        exit()
    initial_prompt()

def create_wallet_seed_execute(passphrase,save_wallet,file_name,password):
    private_key_input = hashlib.sha256(str(passphrase).encode("utf-8"))
    # A very small proportion of inputs are not valid for a private key. Keep hashing the input if necessary
    valid_key_found=0
    while valid_key_found==0:
        try:
            private_key = SigningKey.from_string(private_key_input.digest(), curve=SECP256k1, hashfunc=hashlib.sha256)
            valid_key_found=1
        except:
            private_key_input = hashlib.sha256(private_key_input.digest())
    address=(b"\x00\x00"+hashlib.sha256(private_key.verifying_key.to_string('compressed')).digest()).hex()
    print("Brain wallet address:   " + address)
    if save_wallet==1:
        save_wallet(private_key,file_name,password)
    global active_private_key
    active_private_key = private_key
    global active_address
    active_address=address
    return private_key

def save_wallet(private_key, file_name, hashed_password):
    file_name=str(file_name)
    # Check file name is valid
    if len(file_name)==0:
        file_name = input("Give your wallet file a name? (optional - default: CaptchaCoin Wallet)\n")
        file_name = file_name.strip()
        if len(file_name) == 0:
            file_name="CaptchaCoin Wallet"
    # Check password is valid
    if hashed_password=="":
        password_match=0
        print("You may protect your wallet with a password. To continue without a password, leave the password field blank and press enter.")
        while password_match==0:
            userpass0 = getpass.getpass("Enter password")
            if len(userpass0) > 0:
                userpass1 = getpass.getpass("Enter password again")
                if userpass0 == userpass1:
                    password_match=1
                    print("Password accepted")
                else:
                    print("Passwords didn't match")
            else:
                print("Your wallet will not be password protected")
                password_match=1
        if len(userpass0) > 0:
            hashed_password = hashlib.sha256(str(userpass0).encode("utf-8")).digest()
        else:
            hashed_password = [0]*32
    private_key_bytes=private_key.to_string()
    encrypted_private_key=[(private_key_bytes + hashed_password) % 256 for private_key_bytes, hashed_password in zip(private_key_bytes, hashed_password)]
    decrypted_private_key=[(encrypted_private_key - hashed_password) % 256 for encrypted_private_key, hashed_password in zip(encrypted_private_key, hashed_password)]
    address=b"\x00\x00"+hashlib.sha256(private_key.verifying_key.to_string('compressed')).digest()
    # First 3 bytes denote the wallet as having been created using an alpha version of the wallet software
    # Note that only the private key is password protected. It is still possible to get the address from the file.
    output=list(b"\xff\xff\xff")+encrypted_private_key+list(address)
    if os.path.isfile(file_name+".dat"):
        new_file_name_found = 0
        version=2
        while new_file_name_found==0:
            if os.path.isfile(file_name + " v" + str(version)+".dat"):
                version+=1
            else:
                new_file_name_found=1
        file_name = file_name + " v" + str(version)
    with open( file_name + '.dat', 'wb') as f:
        f.write(bytes(output))
        f.close()
    print("Your wallet has been saved to:\n" + os.getcwd() + "\n\n\n")
    print("The address for receiving Caps is:\n")
    print(address.hex() + "\n")

def access_wallet():
    print("\n\nWhat sort of wallet would you like to access?\n")
    print("[1] A wallet saved on your computer.\n")
    print("[2] A passphrase wallet (brain wallet).")
    user_input = input("Please enter an option (1 or 2):\n")
    if user_input == "1":
        access_wallet_file()
    elif user_input == "2":
        access_wallet_phrase("")
    else:
        print("Input not recognised. Please try again.")
        access_wallet()

def access_wallet_file():
    print("Coming soon")
    time.sleep(5)

def access_wallet_phrase(existing_phrase):
    if len(existing_phrase)==0:
        print("Would you like to view your pass phrase as you type it?\n[1] View as plain text\n[2] Do not show any user input\n")
        valid_input=0
        user_input = input("Please choose 1 or 2\n")
        if user_input=="1" or user_input =="2":
            valid_input=1
        if user_input=="1":
            passphrase = input("Please enter your passphrase:\n")
        elif user_input=="2":
            passphrase = getpass.getpass("Please enter your passphrase:\n")
        else:
            print("Input not recognised. Please try again.")
            access_wallet_phrase()
    else:
        passphrase=existing_phrase
    private_key_input = hashlib.sha256(str(passphrase).encode("utf-8"))
    valid_key_found=0
    while valid_key_found==0:
        try:
            private_key = SigningKey.from_string(private_key_input.digest(), curve=SECP256k1, hashfunc=hashlib.sha256)
            valid_key_found=1
        except:
            private_key_input = hashlib.sha256(private_key_input.digest())
    address=(b"\x00\x00"+hashlib.sha256(private_key.verifying_key.to_string('compressed')).digest()).hex()
    print("The phrase you have entered produces the following address:")
    print(address)
    create_transaction(private_key)

def create_transaction(private_key):
    # Verify private key
    valid_recipient=0
    while valid_recipient==0:
        recipient=input("Enter address of the recipient (68 hex characters):\n")
        try:
            recipient_hex=int(recipient,16)
            if len(recipient)==68:
                valid_recipient=1
            else:
                print("Invalid recipient entered. The address should be 68 hex characters")
        except:
            print("Invalid recipient entered. The address should be 68 hex characters")
    valid_quantity=0
    while valid_quantity==0:
        quantity=input("Enter the number of Caps to send (in standard Cap amounts. One Cap is divisible to 9 decimal places):\n")
        try:
            quantity=int(float(quantity)*1000000000)
            if quantity>0 and quantity<1000000000000000000:
                valid_quantity=1
            else:
                print("Please enter a valid quantity. This must be a number with up to 9 decimal places.")
        except:
            print("Enter a valid quantity. This must be a number with up to 9 decimal places.")
    # 1 byte for transaction type 0, 34 bytes recipient, 8 bytes Cap amount, 5 bytes time, 33 bytes public key, 64 bytes signature
    transaction_output=b'\x00' + bytes.fromhex(recipient) + quantity.to_bytes(8, byteorder='big') + int(time.time()).to_bytes(5, byteorder='big')
    transaction_output += private_key.verifying_key.to_string('compressed') + private_key.sign(transaction_output)
    transaction_output = (len(transaction_output)-128).to_bytes(1, byteorder='big') + transaction_output
    print("\nTransaction created. The transaction output is:\n")
    print(transaction_output.hex())
    print("\nTransaction details:")
    print(str(int(transaction_output[0]+128)) + " - Transaction size (bytes), excluding the transaction size byte(s)")
    print(str(int.from_bytes(transaction_output[1:2],"big")) + " - Transaction type (0 denotes a standard Send transaction)")
    print(str(transaction_output[2:36].hex()) + " - Recipient's address")
    print(str(int.from_bytes(transaction_output[36:44],"big")/1000000000) + " - Caps to send")
    print(str(int.from_bytes(transaction_output[44:49],"big")) + " - unix time transaction was created")
    valid_input=0
    user_input = input("\nWhat you like to do next?\n[1] Create another transaction using the same seed phrase\n[2] Back to the main menu\n[Any other key] Quit\n")
    if user_input=="1" or user_input =="2":
        if user_input=="1":
            access_wallet_phrase(passphrase)
        if user_input=="2":
            initial_prompt()
    else:
        exit()
    

def verify_transaction():
    print("Transaction verification is very limited and will only evaluate a narrow range of transactions. Please update to newer wallet software in the near future.")
    # Allow for unsigned checking?
    valid_transaction=0
    while valid_transaction==0:
        transaction_input=input("Enter your transaction in hex format:\n")
        try:
            transaction_input_test=int(transaction_input,16)
            if len(transaction_input)==292:
                valid_transaction=1
            else:
                print("Invalid transaction entered. The transaction should be 292 hex characters")
        except:
            print("Invalid transaction entered. The transaction should be 292 hex characters")
    print(str(int(transaction_input[0:2],16)+128) + " - Transaction size (bytes), excluding the transaction size byte(s)")
    print(str(int(transaction_input[2:4],16)) + " - Transaction type (0 denotes a standard Send transaction)")
    print(str(transaction_input[4:72]) + " - Recipient's address")
    print(str(int(transaction_input[72:88],16)/1000000000) + " - Caps to send")
    print(str(int(transaction_input[88:98],16)) + " - unix time transaction was created")
    print(str(transaction_input[0:98]) + " - full transaction")
    print(str(transaction_input[98:164]) + " - sender's public key")
    print(str(transaction_input[164:292]) + " - signature")
    try:
        public_key=VerifyingKey.from_string(bytearray.fromhex(transaction_input[98:164]), curve=SECP256k1, hashfunc=hashlib.sha256)
        public_key.verify(bytearray.fromhex(transaction_input[164:292]), bytearray.fromhex(transaction_input[2:98]))
        print("Success! The signature for this transaction matches against the public key.")
    except:
        print("Failure. The signature for this transaction could not be verified against the public key.")
    time.sleep(5)

if __name__ == "__main__":
    main()
