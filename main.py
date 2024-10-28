# import interface library
import tkinter as tk
from tkinter import ttk
# import from other windows
from reg_log import RegLog
# create root window 
# main window with register and login options
root=tk.Tk()
root.title("Copyshh")
root.geometry("300x200")
root.configure(background="black")

# main window title: Label from tk 
welcome = tk.Label(root, text="Welcome to Copyshh", 
                         font=("Courier", 16), 
                         background="black", 
                         foreground="white")
welcome.pack(pady=20)

# style for buttons
style = ttk.Style()
style.configure("TButton", 
                font=("Courier", 12))

# login and register button 
# calls the login class
login_button = ttk.Button(root, 
                          text="Login", 
                          command=lambda: RegLog.open_login_window(root))
#calls the register class
register_button = ttk.Button(root, 
                             text="Register", 
                             command=lambda: RegLog.open_register_window(root))

# pack buttons on window
login_button.pack(pady=10)
register_button.pack(pady=10)

# start tkinter main loop
root.mainloop()