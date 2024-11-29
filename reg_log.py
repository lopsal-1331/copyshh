#import tkinter
import tkinter as tk 
from tkinter import ttk 
from tkinter import messagebox
# import other classes

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

    def register(user:str, pas:str, pas2:str, campus):
        from encryption import Encryption
        from servers import CertificateAuthority
        from json_manager import Json
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        # passwords should match
        if pas!=pas2: 
            messagebox.showerror('Error', 'Passwords do not match.')
            return
        '''if len(pas)<8: 
            messagebox.showerror('Error','Password should be at  least 8 characters')
            return'''
        
        # see if the username already exists in database
        user_stored=Json.get_user_data(user)
        if user_stored:
            messagebox.showerror('Error', 'Username already taken.')
            return
        
        # generate token and salt for user
        token, salt = Encryption.get_token_salt(pas, None)
        from json_manager import Json

        # store data in database
        Json.store_data(user, token, salt)
        messagebox.showinfo('Success', 'User registered.')

        # reference map for servers
        campus_to_server = {
            'Colmenarejo': 'apartamentos_colmena',
            'Leganés': 'apartamentos_lagarto',
            'Puerta de Toledo': 'apartamentos_toldos',
            'Getafe': 'apartamentos_gafe'
        }

        campus_name = campus_to_server.get(campus)
        if not campus: 
            messagebox.showerror('Error', 'Campus not found')
        
        # load users corresponding ca cecrtificate and private key to sign their certificate
        ca_cert_path=f'CA/{campus_name}/cert.pem'
        ca_key_path = f'CA/{campus_name}/key.pem'
        with open(ca_cert_path, "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read())
        with open(ca_key_path, "rb") as f:
            ca_key = serialization.load_pem_private_key(f.read(), None)
        
        # create certificate for user
        user_key, user_cert = CertificateAuthority.create_ca(
            user, 
            issuer_cert=ca_cert,
            issuer_key=ca_key)

        # save key and certificate in user server
        cert_path = f'{user}_server/{user}_cert.pem'
        key_path = f'{user}_server/{user}privkey.pem'
        CertificateAuthority.save_cert_and_key(user_cert, user_key, cert_path, key_path)

        # show success mesasge
        messagebox.showinfo('Success', f'Certification granted by {campus}')
    
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
        from user_main import UserMain
        UserMain.user_main_window(main, user)
