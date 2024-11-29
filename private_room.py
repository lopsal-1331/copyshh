import tkinter as tk
import os

class PrivateRoom:
    from encryption import Encryption

    def __init__(self, main, code, roomate, user):
        self.code = code
        self.roomate = roomate
        self.user = user

        self.priv = tk.Toplevel(main)
        self.priv.title('PrivateRoom')
        self.priv.geometry("500x500")

        label = tk.Label(self.priv, text=f"Welcome to the Private Room: {code}")
        label.pack(pady=20)
        
        self.message_area = tk.Text(self.priv, height=15, width=50, state=tk.DISABLED)
        self.message_area.pack(pady=10)

        self.message_entry = tk.Entry(self.priv, width=40)
        self.message_entry.pack(pady=5)

        send_button = tk.Button(self.priv, text="Send Message", command=self.send_message)
        send_button.pack(pady=5)

        refresh_button = tk.Button(self.priv, text="Refresh Messages", command=self.refresh)
        refresh_button.pack(pady=5)

        self.priv.after(3000, self.refresh)

    def send_message(self):
        from encryption import Encryption
        from json_manager import Json

        chacha_key = Encryption.get_chacha_key(self.user, self.roomate, self.code)
        message = self.message_entry.get()
        if not message:
            return

        nonce, emessage = Encryption.chacha_encrypt(chacha_key, message.encode('utf-8'))

        sender_private_key = Encryption.load_private_key(f'{self.user}_server/{self.user}privkey.pem')
        signature = Encryption.rsa_sign(sender_private_key, emessage)
        
        message_file = f'{self.roomate}_server/{self.user}_{self.code}_messages.json'
        Json.append_to_file(message_file, {
            'message': emessage.hex(),
            'nonce': nonce.hex(),
            'signature': signature.hex(),
        })
        self.message_entry.delete(0, tk.END)

    def refresh(self):
        from encryption import Encryption
        from json_manager import Json

        chacha_key = Encryption.get_chacha_key(self.user, self.roomate, self.code)
        messages_file = f'{self.user}_server/{self.roomate}_{self.code}_messages.json'
        emessages = Json.read_from_json(messages_file)

        self.message_area.config(state=tk.NORMAL)
        for text in emessages:
            nonce = bytes.fromhex(text['nonce'])
            etext = bytes.fromhex(text['message'])
            signature = bytes.fromhex(text['signature'])

            sender_public_key = Encryption.load_public_key(f'{self.user}_server/{self.roomate}publickey.pem')
            if not Encryption.rsa_verify(sender_public_key, signature, etext):
                self.message_area.insert(tk.END, f'{self.roomate}: Signature invalid, message skipped\n')
                continue

            dtext = Encryption.chacha_decrypt(chacha_key, nonce, etext).decode('utf-8')
            self.message_area.insert(tk.END, f'{self.roomate}: {dtext}\n')

        Json.clear_file(messages_file)
        self.message_area.config(state=tk.DISABLED)

        self.message_area.after(3000, self.refresh)
