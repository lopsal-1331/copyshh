#import tkinter
import tkinter as tk 
from tkinter import ttk 
from tkinter import messagebox
# import other classes

class RegLog: 
    # function to open the registration window
    @staticmethod
    def open_register_window(cur_window):
        # create new window
        regw = tk.Toplevel(cur_window)
        regw.title("Register")
        regw.geometry("350x200")
        
        # username input
        ttk.Label(regw, 
                  text="Username", 
                  font = "Courier").grid(row=0, 
                                         column=0, 
                                         padx=10, 
                                         pady=10)
        new_usr=ttk.Entry(regw)
        new_usr.grid(row=0, column=1, padx=10, pady=10)
        
        # password input
        ttk.Label(regw, 
                  text="Password", 
                  font="Courier").grid(row=1, 
                                       column=0, 
                                       padx=10, 
                                       pady=10)
        usr_pass = ttk.Entry(regw, show="·")
        usr_pass.grid(row=1, column=1, padx=10, pady=10)
        
        # confirmation of password input
        ttk.Label(regw, 
                  text="Confirm Password", 
                  font="Courier").grid(row=2, 
                                       column=0, 
                                       padx=10, 
                                       pady=10)
        usr_pass_confirmation = ttk.Entry(regw, show="·")
        usr_pass_confirmation.grid(row=2, column=1, padx=10, pady=10)
        
        # registration button 
        # calls function that processes registration data
        ttk.Button(
            regw,
            text="Register", 
            command=lambda: RegLog.register(
                new_usr.get(),
                usr_pass.get(), 
                usr_pass_confirmation.get()
            )
        ).grid(row=3, column=0, columnspan=2, padx=10, pady=10, sticky="ew")

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

    def register(user:str, pas:str, pas2:str):
        from encryption import Encryption
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
        filename_priv=user+"_server/"+ user+'privkey.pem'
        filename_public=user+"_server/"+ user+'publickey.pem'
        filename_open_server="open_server/"+user+'publickey.pem'
        Encryption.save_private_key(privk,filename_priv,user)
        Encryption.save_public_key(publick, filename_public, user)
        Encryption.save_public_key(publick, filename_open_server, user)
        from user_main import UserMain
        UserMain.user_main_window(main, user)
