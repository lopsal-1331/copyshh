#import tkinter
import tkinter as tk 
from tkinter import ttk 
from tkinter import messagebox
import os
from cryptography.hazmat.primitives import serialization



class RegLog: 
    # function to open the registration window
    @staticmethod
    def open_register_window(cur_window): 
        # create a new window
        regw = tk.Toplevel(cur_window)
        regw.title('Register')
        regw.geometry('400x250')
        
        # username input
        ttk.Label(
            regw, 
            text = 'Username', 
            font = 'Courier'
        ).grid(row=0, column=0, padx=10, pady=10)
        new_usr = ttk.Entry(regw)
        new_usr.grid(row=0, column=1, padx=10, pady=10)

        # password input
        ttk.Label (
            regw, 
            text='Password', 
            font='Courier'
        ).grid(row=1, column=0, padx=10, pady=10)
        usr_pass = ttk.Entry(regw, show='·')
        usr_pass.grid(row=1, column=1, padx=10, pady=10)

        # confirmation of password
        ttk.Label (
            regw, 
            text='Confirm Password', 
            font='Courier'
        ).grid(row=2, column=0, padx=10, pady=10)
        usr_pass_confirmation = ttk.Entry(regw, show='·')
        usr_pass_confirmation.grid(row=2, column=1, padx=10, pady=10)

        # campus dropdown
        ttk.Label(
            regw, 
            text='Campus', 
            font='Courier'
        ).grid(row=3, column=0, padx=10, pady=10)
        campus = tk.StringVar()
        campus_select = ttk.Combobox(
            regw, 
            textvariable=campus, 
            values=['Colmenarejo', 'Leganés', 'Getafe', 'Puerta de Toledo'], 
            state='readonly' # no option to write in the drop down
        )
        campus_select.grid(row=3, column=1, padx=10, pady=10)
        campus_select.current(0) # selects Colmenarejo as default element

        # register button
        ttk.Button (
            regw, 
            text='Register', 
            command=lambda:RegLog.register(
                new_usr.get(), 
                usr_pass.get(), 
                usr_pass_confirmation.get(), 
                campus_select.get()
            )
        ).grid(row=4, column=0, columnspan=2, padx=10, pady=10)

    @staticmethod
    def open_login_window(main):
    # open new window for log in 
        log = tk.Toplevel(main)
        log.title("Login")
        log.geometry("250x175")
        
        # login neccessary data
        # get username
        ttk.Label(log, 
                    text="Username", 
                    font="Courier").grid(row=0, column=0, padx=10, pady=10, sticky="W")
        username_entry = ttk.Entry(log)
        username_entry.grid(row=0, column=1, padx=10, pady=10)
        
        # get password
        ttk.Label(log, 
                    text="Password", 
                    font="Courier").grid(row=1, column=0, padx=10, pady=10, sticky="W")
        
        password_entry = ttk.Entry(log, show="*")
        password_entry.grid(row=1, column=1, padx=10, pady=10)
        
        # Log in button
        ttk.Button(log, text="Login", 
                    command=lambda: RegLog.login(
                        username_entry.get(), 
                        password_entry.get(), main)).grid(row=2, column=0, columnspan=2, pady=10)

    def register(user:str, pas:str, pas2:str, campus:str):
        from encryption import Encryption
        from servers import Servers
        from json_manager import Json

        if pas!=pas2: 
            messagebox.showerror('Error', 'Passwords do not match.')
            return
        if len(pas)<8: 
            messagebox.showerror('Error','Password should be at least 8 characters')
            return
        from json_manager import Json
        user_stored=Json.get_user_data(user)
        if user_stored:
            messagebox.showerror('Error', 'Username already taken.')
            return
        token, salt = Encryption.get_token_salt(pas, None)
        from json_manager import Json
        Json.store_data(user, token, salt)
        messagebox.showinfo('Success', 'User registered.')

        Servers.initialize_authorities() # ensure the ca are initialized

        campus_to_server = {
            'Colmenarejo' : 'apartamentos_colmena', 
            'Leganés' : 'apartamentos_lagarto',
            'Puerta de Toledo' : 'apartamentos_toldos', 
            'Getafe' : 'apartamentos_gafe'
        }

        campus_server_name= campus_to_server.get(campus)
        if campus_server_name: 
            # find the corresponding campus server 
            campus_server = Servers.servers_instances.get(campus_server_name)
            # generates keys for the user
            user_private_key, user_public_key = Encryption.generate_keys()
            Encryption.save_private_key(user_private_key, f'{user}_server/{user}privkey.pem', user)
            Encryption.save_public_key(user_public_key, f'{user}_server/{user}publickey.pem', user)

            # create and sign CSR of user using the campus server
            user_cert = campus_server.create_and_sign_csr(user, user_public_key)

            # save the signed certificate
            user_cert_path = f'{user}_server/{user}_certificate.pem'
            with open(user_cert_path, 'wb') as cert_file:
                cert_file.write(user_cert.public_bytes(serialization.Encoding.PEM))

            messagebox.showinfo('Success', f'{user} certificate generated and saved.')

    
    def login(user:str, pas:str, main):
        from encryption import Encryption
        from json_manager import Json
        user_stored=Json.get_user_data(user)
        if not user_stored: 
            messagebox.showerror('Error', 'This username does not exist')
            return 
        stored_token=user_stored['token']
        salt=user_stored['salt']
        new_token,_ = Encryption.get_token_salt(pas,salt)
        if new_token!=stored_token: 
            messagebox.showerror('Error', 'Incorrect Password')
            return 
        messagebox.showinfo('Success', 'Welcome to the Copyshh apartment building.')
        privk, publick = Encryption.generate_keys()
        from user_main import UserMain
        UserMain.user_main_window(main, user)
