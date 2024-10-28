import tkinter as tk
from tkinter import messagebox
import os

class PrivateRoom: 
    from encryption import Encryption
    # for the same session lets use the same hmac key 
    hmac_key = Encryption.generate_hmac_key()


    def room_window(main, code, roomate, user):
        priv=tk.Toplevel(main)
        priv.title('PrivateRoom')
        priv.geometry("500x500")
        label = tk.Label(priv,text=f"Welcome to the Private Room: {code}")
        label.pack(pady=20)
        
        PrivateRoom.message_area = tk.Text(priv, height=15, width=50, state=tk.DISABLED)
        PrivateRoom.message_area.pack(pady=10)

        PrivateRoom.message_entry = tk.Entry(priv, width=40)
        PrivateRoom.message_entry.pack(pady=5)

        send_button = tk.Button(priv, text="Send Message", command=lambda: PrivateRoom.send_message(code, roomate, user))
        send_button.pack(pady=5)

        refresh_button = tk.Button(priv, text="Refresh Messages", command=lambda: PrivateRoom.refresh(code, roomate, user))
        refresh_button.pack(pady=5)
    
    def send_message(code, roomate, user):
        # function to send message to receiver
        from encryption import Encryption
        from json_manager import Json
        # 1. load the chacha key
        chacha_key=Encryption.get_chacha_key(user, roomate, code)

        # 2. get the message from entry. 
        message= PrivateRoom.message_entry.get()
        if not message: 
            return 
        
        # 3. encrypt the message
        nonce, emessage=Encryption.chacha_encrypt(chacha_key, message.encode('utf-8'))

        # 4. Generate hmac signature
        hmac_signature=Encryption.sign_with_hmac(PrivateRoom.hmac_key, emessage)

        # 5. Store encrypted message, nonce and message in json
        message_file=f'{roomate}_server/{user}_{code}_messages.json'
        Json.append_to_file(message_file, 
                            {
                                'message':emessage.hex(), 
                                'nonce': nonce.hex(), 
                                'hmac':hmac_signature.hex()
                            })
        
        # play a sending sound
        os.system('aplay send.wav')
        
        # Clear entry field
        PrivateRoom.message_entry.delete(0, tk.END)

    
    def refresh(code, roomate, user):
        from encryption import Encryption
        from json_manager import Json
        # Load chacha key for decryption
        chacha_key = Encryption.get_chacha_key(user, roomate, code)

        # Load messages from my server
        messages_file=f'{user}_server/{roomate}_{code}_messages.json'
        emessages=Json.read_from_json(messages_file)

        # Decrypt and display the messages
        PrivateRoom.message_area.config(state=tk.NORMAL)
        for text in emessages: 
            nonce = bytes.fromhex(text['nonce'])
            etext = bytes.fromhex(text['message'])
            hmac = bytes.fromhex(text['hmac'])

            # verify mac 
            if Encryption.verify_hmac(
                PrivateRoom.hmac_key, etext, hmac
            ):
                dtext= Encryption.chacha_decrypt(chacha_key, nonce, etext)
                PrivateRoom.message_area.insert(
                    tk.END, f'{roomate}: {dtext}\n'
                )
            else: 
                PrivateRoom.message_area.insert(
                    tk.END, f'Warning: Recieved an unauthenticated message \n '
                )
        Json.clear_file(messages_file)
        PrivateRoom.message_area.config(state=tk.DISABLED)