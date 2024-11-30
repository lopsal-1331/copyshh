import tkinter as tk
from tkinter import messagebox

class PrivateRoom:
    from encryption import Encryption
    
    def __init__(self, main, code, roomate, user):
        # We use _init__ to be able to open two chats at the same time
        self.code = code
        self.roomate = roomate
        self.user = user

        # Create a separate window for each instance
        self.priv = tk.Toplevel(main)
        self.priv.title('PrivateRoom')
        self.priv.geometry("500x500")

        label = tk.Label(self.priv, text=f"Welcome to the Private Room: {code}")
        label.pack(pady=20)
        
        # Instance-specific message area and entry field
        self.message_area = tk.Text(self.priv, height=15, width=50, state=tk.DISABLED)
        self.message_area.pack(pady=10)

        self.message_entry = tk.Entry(self.priv, width=40)
        self.message_entry.pack(pady=5)

        send_button = tk.Button(self.priv, text="Send Message", command=self.send_message)
        send_button.pack(pady=5)

        refresh_button = tk.Button(self.priv, text="Refresh Messages", command=self.refresh)
        refresh_button.pack(pady=5)

        # Start periodic refresh for this instance
        self.priv.after(3000, self.refresh)

    def send_message(self):
        from encryption import Encryption
        from json_manager import Json

        # Load ChaCha key and encrypt message
        chacha_key = Encryption.get_chacha_key(self.user, self.roomate, self.code)
        message = self.message_entry.get()
        if not message:
            return

        # save nonce and encrypted message
        nonce, emessage = Encryption.chacha_encrypt(chacha_key, message.encode('utf-8'))

        private_key = Encryption.load_private_key(f'{self.user}_server/{self.user}privkey.pem')
        signature = Encryption.rsa_sign(private_key, emessage)

        # save the message as a json dictionary
        message_file = f'{self.roomate}_server/{self.user}_{self.code}_messages.json'
        Json.append_to_file(message_file, {
            'message': emessage.hex(),
            'nonce': nonce.hex(),
            'signature' : signature.hex()
        })
        self.message_entry.delete(0, tk.END)

    def refresh(self):
        from encryption import Encryption
        from json_manager import Json

        # load the chacha key
        chacha_key = Encryption.get_chacha_key(self.user, self.roomate, self.code)
        messages_file = f'{self.user}_server/{self.roomate}_{self.code}_messages.json'
        # get the messages inbox file
        emessages = Json.read_from_json(messages_file)
        
        # for each message that has been sent and not delivered
        self.message_area.config(state=tk.NORMAL)
        public_key = Encryption.load_public_key(f'{self.roomate}_server/{self.user}publickey.pem')

        for text in emessages:
            nonce = bytes.fromhex(text['nonce'])
            etext = bytes.fromhex(text['message'])
            signature = bytes.fromhex(text['signature'])


            verified = Encryption.rsa_verify(public_key, etext, signature)
            if not verified: 
                messagebox.showerror('Error', 'There was tampering with the message, you should not trust your roomate')
                self.priv.destroy()
            else: 
                dtext = Encryption.chacha_decrypt(chacha_key, nonce, etext).decode('utf-8')
                self.message_area.insert(tk.END, f'{self.roomate}: {dtext}\n')


        Json.clear_file(messages_file)
        self.message_area.config(state=tk.DISABLED)

        # Schedule the next refresh for this instance
        self.message_area.after(3000, self.refresh)
