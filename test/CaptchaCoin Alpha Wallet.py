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
    # Record the time whenever the user makes an action as a source of randomness for wallet generation
    global random_time
    random_time = str(time.time()).encode("utf-8")
    print("CaptchaCoin Wallet Software - Alpha release")
    print("This version of the CaptchaCoin wallet software is for testing only.\nPlease only use it with very small quantities of Caps.\n")
    print("Select one of the following options:\n[1] Create a wallet\n[2] Access a wallet and create a transaction\n[3] Verify a transaction\n")
    user_input = input("Please enter an option (1, 2 or 3): ")
    random_time += str(time.time()).encode("utf-8")
    if user_input == "1":
        create_wallet()
    elif user_input == "2":
        access_wallet()
    elif user_input == "3":
        verify_transaction()
    else:
        print("Input not recognised. Please try again.")
        main()

def create_wallet():
    global random_time
    print("\n\nWhat sort of wallet would you like to create?\n")
    print("[1] A randomly generated wallet. This will create a file on your computer containing all of the wallet information.\nIf you lose this file, you will lose the wallet and any funds.\n")
    print("[2] A passphrase wallet (brain wallet). You will enter a series of words as your seed.\nIf you forget the series of words, you will lose the wallet and any funds.\n")
    user_input = input("Please enter an option (1 or 2): ")
    random_time += str(time.time()).encode("utf-8")
    if user_input == "1":
        create_wallet_random()
    elif user_input == "2":
        create_wallet_seed()
    else:
        print("Input not recognised. Please try again.")
        create_wallet()

def create_wallet_random():
    global random_time
    print("This will be made available during the next release")
    time.sleep(3)
    main()
    exit()
    print("\n\nYour wallet will be created using randomness from your computer, as well as user-generated randomness\n")
    sufficient_randomness0=0
    user_random = ""
    while sufficient_randomness0==0:
        if len(user_random) > 31:
            random_time += str(time.time()).encode("utf-8")
            sufficient_randomness0 = 1
        else:
            random_time += str(time.time()).encode("utf-8")
            user_random += getpass.getpass("Please randomly press buttons on your keyboard, then push the Enter key")
    print("")
    sufficient_randomness1=0
    while sufficient_randomness1==0:
        random_time += str(time.time()).encode("utf-8")
        if len(user_random) > 63:
            sufficient_randomness1 = 1
        else:
            user_random += getpass.getpass("To add further randomness, please randomly press buttons on your keyboard, then push Enter")
    password_match=0
    print("Your wallet will be protected with a password. This should NOT be the same as your passphrase.")
    while password_match==0:
        userpass0 = getpass.getpass("Enter password")
        random_time += str(time.time()).encode("utf-8")
        userpass1 = getpass.getpass("Enter password again")
        random_time += str(time.time()).encode("utf-8")
        if userpass0 == userpass1:
            password_match=1
        else:
            print("Passwords didn't match")
    file_name="CaptchaCoin Wallet "
    file_name += input("Give your wallet file a name? (optional)\nWarning! This will overwrite any wallets with the same name, including no name.\n")
    file_name = file_name.strip()
    random_time += str(time.time()).encode("utf-8")
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
    hashed_password = hashlib.sha256(str(userpass0).encode("utf-8")).digest()
    hashed_private_key=private_key.to_string()
    encrypted_private_key=[(hashed_private_key + hashed_password) % 256 for hashed_private_key, hashed_password in zip(hashed_private_key, hashed_password)]
    decrypted_private_key=[(encrypted_private_key - hashed_password) % 256 for encrypted_private_key, hashed_password in zip(encrypted_private_key, hashed_password)]
    address=list(hashlib.sha256(private_key.verifying_key.to_string('compressed')).digest())
    output=encrypted_private_key+address
    with open( file_name + '.cap', 'wb') as f:
        f.write(bytes(output))
        f.close()
    print("Your wallet has been saved to:\n" + os.getcwd() + "\n\n\n")
    time.sleep(5)
    main()

def create_wallet_seed():
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
    private_key_input = hashlib.sha256(str(passphrase0).encode("utf-8"))
    # A very small proportion of inputs are not valid for a private key. Keep hashing the input if necessary
    valid_key_found=0
    while valid_key_found==0:
        try:
            private_key = SigningKey.from_string(private_key_input.digest(), curve=SECP256k1, hashfunc=hashlib.sha256)
            valid_key_found=1
        except:
            private_key_input = hashlib.sha256(private_key_input.digest())
    address=(b"\x00\x00"+hashlib.sha256(private_key.verifying_key.to_string('compressed')).digest()).hex()
    print("Your brain wallet has been created.\nThe address for receiving Caps is:\n")
    print(address + "\n")
    time.sleep(3)
    user_input = input("\nWhat you like to do next?\n[1] Mine Caps to this address\n[2] Back to the main menu\n[Any other key] Quit\n")
    print("\n\n")
    if user_input=="1" or user_input =="2":
        if user_input=="1":
            webbrowser.open('https://www.captchacoin.net/earn/login-user.php?' + address)
        if user_input=="2":
            main()
    else:
        exit()
    main()

def access_wallet():
    print("This will be made available during the next update")
    time.sleep(3)
    main()
    exit()
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
            main()
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