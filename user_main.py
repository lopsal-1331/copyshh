import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
from private_room import PrivateRoom
import os 
'''
FUNCTIONS AND INTERFACE OF USER MAIN WINDOW AFTER LOGIN
'''
class UserMain: 
    @staticmethod
    def user_main_window(main, username):
        # Initialize the main window
        usr_main = tk.Toplevel(main)
        usr_main.title("My Apartment")
        usr_main.geometry("300x300") 

        # Label for window title
        ttk.Label(usr_main, text="My Copyshh Apartment", 
                font=("Courier", 16)).grid(row=0, column=0, padx=10, pady=10)

        # Button to create a new room (+)
        ttk.Button(usr_main, text="Put room for sale", 
                command=lambda: UserMain.create_room(usr_main, username)).grid(row=1, column=0, padx=10, pady=10)
        
        # Button to find invitations
        ttk.Button(usr_main, text="Look offers", 
                command=lambda: UserMain.find_invitations(username)).grid(row=2, column=0, padx=10, pady=10)
        
        # Button to enter room 
        ttk.Button(usr_main, text="Enter apartment", 
                command=lambda: UserMain.enter_room(main, username)).grid(row=3, column=0, padx=10, pady=10)


        # Button to close the main window -- logic not complete yet
        ttk.Button(usr_main, text="Close", 
                command=lambda: UserMain.destroy_all(username)).grid(row=4, column=0, padx=10, pady=10)

    @staticmethod
    def create_room(main, user): 
        # Interface to create a new room
        # Entry = username of the user ypu want to be 'roommates' with
        room = tk.Toplevel(main)
        room.title('Find Roomates')
        room.geometry("300x300")
        ttk.Label(
            room, 
            text="Roomate",
            font=("Courier", 16)
        ).grid(row=0, column=0, padx=10, pady=10)
        ttk.Label(room, 
                  text="Username", 
                  font="Courier"
                  ).grid(row=1, column=0, padx=10, pady=10, sticky="W")
        usr = ttk.Entry(room)
        usr.grid(row=1, column=1, padx=10, pady=10)
        ttk.Button(
            room,
            text="Send Invitation", 
            command=lambda: UserMain.send_invitation(user, usr.get())
            ).grid(row=3, column=0, columnspan=2, pady=10)

    @staticmethod
    def send_invitation(sender, receiver):
        from encryption import Encryption 
        # this function  mimics both ends of the transaction.
        # sender loads the public key of the receiver -from OPEN SERVER
        receiver_publickey_path = f'open_server/{receiver}publickey.pem' 
        receiver_publickey = Encryption.load_public_key(receiver_publickey_path)

        # For signing, sender also loads their private key
        sender_privatekey_path=f'{sender}_server/{sender}privkey.pem'
        sender_privatekey=Encryption.load_private_key(sender_privatekey_path)

        # the receiver opens their own private key --> THEIR OWN SERVER
        receiver_privatekey_path=f'{receiver}_server/{receiver}privkey.pem'
        receiver_privatekey=Encryption.load_private_key(receiver_privatekey_path)

        # the receiver loads the public key of the sender to make sure the data is authenticated
        sender_publickey_path=f'open_server/{sender}publickey.pem'
        sender_publickey=Encryption.load_public_key(sender_publickey_path)
        
        # Generate a room code and a chacha key for communication inside the private room.
        chacha_key, code = Encryption.generate_chacha_key_and_code()

        # Create a message for sender ---> Communicate code
        messagebox.showinfo('Room Created!', f'Write down this code! {code.decode('utf-8')}, QUICK!!. Processing invitation...')

        # Automatically the chacha key is saved in the sender's server so he can enter the room. 
        # the file will be called {rommate}_{roomcode}_key.pem for later identification
        Encryption.save_chacha_key(sender, chacha_key, f'{receiver}_{code.decode('utf-8')}')

        # Encrypt both the key and the chacha key  using RSA - public key of receiver
        echacha = Encryption.rsa_encrypt(receiver_publickey, chacha_key)
        ecode = Encryption.rsa_encrypt(receiver_publickey, code)
        
        # We are also sending a signature to make sure data is authenticated.
        data_to_sign=echacha+ecode
        signature = Encryption.rsa_sign(sender_privatekey, data_to_sign)

        from json_manager import Json  

        # We save in different files the encrypted chachakey, the encrypted code and a signature
        Json.save_to_file(f'{receiver}_server/{sender}_chacha_key.bin', echacha)
        Json.save_to_file(f'{receiver}_server/{sender}_code.bin', ecode)
        Json.save_to_file(f'{receiver}_server/{sender}_signature.bin', signature)
        
        # Messange to sender to communicate the data has been sent
        messagebox.showinfo('Success!', f'Invitation sent to {receiver}')
        
        # ------- Reciever side -------
        # We load from the files the encrypted data 
        encrypted_chacha_key_from_file = Json.read_from_file(f'{receiver}_server/{sender}_chacha_key.bin')
        encrypted_code_from_file = Json.read_from_file(f'{receiver}_server/{sender}_code.bin')
        signature_from_file=Json.read_from_file(f'{receiver}_server/{sender}_signature.bin')

        #Before encrypting the server will make sure the data is authenticated
        data_to_verify= encrypted_chacha_key_from_file + encrypted_code_from_file
        if Encryption.rsa_verify(sender_publickey, data_to_verify, signature_from_file):
            # Only if data verified, we continue to decrypt data
            decrypted_chacha_key = Encryption.rsa_decrypt(receiver_privatekey, encrypted_chacha_key_from_file)
            decrypted_code = Encryption.rsa_decrypt(receiver_privatekey, encrypted_code_from_file)
            
            # Now that everything is decrypted, we only save de chacha key on the receiver's side
            # the name fo the file will be {sender}_{room_code}_key.bin so we're able to identify both room and roommate
            Encryption.save_chacha_key(receiver, decrypted_chacha_key, f'{sender}_{decrypted_code.decode('utf-8')}')
            # Now lets remove all the files that were created for the exchange
            os.remove(f'{receiver}_server/{sender}_chacha_key.bin')
            os.remove(f'{receiver}_server/{sender}_code.bin')
            os.remove(f'{receiver}_server/{sender}_signature.bin')

        else: 
            print('ERROR WITH SIGNATURE')
        
    @staticmethod
    def find_invitations(user):
        from json_manager import Json
        # search files in user's server ending in _key.bin
        invitations=Json.find_files_with_suffix(f'{user}_server', '_key.bin')
        if not invitations:
            messagebox.showinfo('No Luck!', 'No one sent you an invitation')
            return
        first_offer=invitations[0]
        # we get from the file name both the sender and the code
        sender=first_offer.split('_')[0]
        code=first_offer.split('_')[1]
        messagebox.showinfo('Lucky you!', f'{sender} sent you an invitation! Write this code down {code}, QUICK!!!')

    @staticmethod
    def enter_room(main, user):
        # Interface for entering a room --> Entry: room code
        from json_manager import Json
        enter_room_window = tk.Toplevel(main)
        enter_room_window.title("Enter Room Code")
        enter_room_window.geometry("300x150")
        tk.Label(enter_room_window, text="Enter Room Code:").pack(pady=10)

        room_code_entry = tk.Entry(enter_room_window)
        room_code_entry.pack(pady=5)

        def submit_code():
            room_code = room_code_entry.get()
            if room_code:
                # if we can find a file that ends in {room_code}_key.bin, we are invited to the apartment
                invitation=Json.find_files_with_suffix(f'{user}_server', f'{room_code}_key.bin')
                if not invitation: 
                    # if there's not an invitation in our server related to this code, nothing happens.
                    messagebox.showerror('Error', 'You are not invited to THAT apartment.')
                    return
                invitation =invitation[0]
                sender=invitation.split('_')[0]
                PrivateRoom(main, room_code, sender, user)
            else:
                messagebox.showwarning("Input Error", "Please enter a room code.")

        submit_button = tk.Button(enter_room_window, text="Submit", command=submit_code)
        submit_button.pack(pady=20)
    
    @staticmethod
    def destroy_all(user): 
        # destroys all the invitations the user has in this session (all files with chacha keys)
        from json_manager import Json
        # we save all the filenames correlated to a chacha key from a room (ends in _key.bin)
        invitations = Json.find_files_with_suffix(f'{user}_server', '_key.bin')
        if not invitations: 
            return 
        else: 
            # for each invitation, we delete the file
            for invitation in invitations: 
                os.remove(f'{user}_server/{invitation}')
