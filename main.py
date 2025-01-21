from tkinter import *
from tkinter import ttk
import hashlib
import json
def registration():
    user_name = username_entry.get()
    user_password = password_entry.get()
    md5_hash = hashlib.new('md5')
    md5_hash.update(user_password.encode())
    hash_password = md5_hash.hexdigest()
    with open("data_base.json") as fp:
        json_file = json.load(fp)
    json_file[user_name] = hash_password
    with open("data_base.json", 'w') as fp:
        json.dump(json_file, fp)
    say_reg_label = Label(text="You registered!)", font=("Arial", 18))
    say_reg_label.place(x=200, y=550)
def autorisation():
    user = username_entry.get()
    password = password_entry.get()
    with open('data_base.json', 'r') as jsonFile:
        jsonFile = json.load(jsonFile)
    md5_hash = hashlib.new('md5')
    md5_hash.update(password.encode())
    hash_password = md5_hash.hexdigest()
    with open("data_base.json") as fp:
        json_file = json.load(fp)
    try:
        if json_file[user]==hash_password:
            say_reg_label = Label(text="You sign up to account!)", font=("Arial", 18))
            say_reg_label.place(x=150, y=550)
        else:
            say_reg_label = Label(text="Uncorrect password(", font=("Arial", 18))
            say_reg_label.place(x=170, y=550)
    except KeyError:
        say_reg_label = Label(text="User not found(", font=("Arial", 18))
        say_reg_label.place(x=200, y=550)
def reg_window():
    global username_entry
    global password_entry
    root.destroy()
    regWindow = Tk()
    regWindow.title("Registration")
    regWindow.geometry("600x600")
    regWindow.resizable(False, False)
    sign_in_label = Label(text="Sign in", font=("Arial", 24))
    sign_in_label.place(x=240, y=180)
    username_label = Label(text="Username")
    username_label.place(x=180, y=250)
    password_label = Label(text="Password")
    password_label.place(x=180, y=300)
    username_entry = ttk.Entry()
    username_entry.place(x=250, y=250)
    password_entry = ttk.Entry()
    password_entry.place(x=250, y=300)
    sign_in_btn = ttk.Button(text="Sign in", command=registration)
    sign_in_btn.place(x=250, y=400)
    regWindow.mainloop()
def auto_window():
    global username_entry
    global password_entry
    root.destroy()
    autoWindow = Tk()
    autoWindow.title("Autorisation")
    autoWindow.geometry("600x600")
    autoWindow.resizable(False, False)
    sign_up_label = Label(text="Sign up", font=("Arial", 24))
    sign_up_label.place(x=240, y=180)
    username_label = Label(text="Username")
    username_label.place(x=180, y=250)
    password_label = Label(text="Password")
    password_label.place(x=180, y=300)
    username_entry = ttk.Entry()
    username_entry.place(x=250, y=250)
    password_entry = ttk.Entry()
    password_entry.place(x=250, y=300)
    sign_up_btn = ttk.Button(text="Sign up", command=autorisation)
    sign_up_btn.place(x=250, y=400)
    autoWindow.mainloop()
root = Tk()
root.title("TkinterTestingWindow")
root.geometry("600x600")
root.iconbitmap(True, default="png-klev-club-g5e5-p-doksbin-png-6.ico")
root.resizable(False, False)

say_hello_label = Label(text="Hello my dear user!)")
say_hello_label.pack(expand=True, anchor="n", pady=50)
reg_btn = ttk.Button(text="Sign in", command=reg_window)
reg_btn.pack(expand=True, side=RIGHT, padx=100, pady=100, ipadx=10, ipady=10)
auto_btn = ttk.Button(text="Sign up", command=auto_window)
auto_btn.pack(expand=True, side=LEFT, padx=100, pady=100, ipadx=10, ipady=10)
root.mainloop()
