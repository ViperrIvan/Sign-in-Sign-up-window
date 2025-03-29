from tkinter import *
from tkinter import ttk
import hashlib
import json
import os

class Logger:
    _instance = None

    def __new__(cls, log_file="logs.txt",  *args, **kwargs):
        if not cls._instance:
            cls._instance = super(Logger, cls).__new__(cls, *args, **kwargs)
        return cls._instance

    def log(self, message):
        pass

    def load_logs(self):
        pass
    
    def save_logs(self):
        pass
    
class UserDatabase:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(UserDatabase, cls).__new__(cls)
            cls._instance._initialize()
        return cls._instance

    def _initialize(self):
        self.data_file = "data_base.json"
        if not os.path.exists(self.data_file):
            with open(self.data_file, 'w') as fp:
                json.dump({}, fp)

    def load_data(self):
        with open(self.data_file) as fp:
            return json.load(fp)

    def save_data(self, data):
        with open(self.data_file, 'w') as fp:
            json.dump(data, fp)

    def user_exists(self, username):
        data = self.load_data()
        return username in data

    def add_user(self, username, hashed_password):
        data = self.load_data()
        data[username] = hashed_password
        self.save_data(data)


class AuthApp:
    def __init__(self):
        self.root = Tk()
        self.root.title("TkinterTestingWindow")
        self.root.geometry("600x600")
        self.root.resizable(False, False)
        self.init_ui()

    def init_ui(self):
        self.say_hello_label = Label(self.root, text="Hello my dear user!)")
        self.say_hello_label.pack(expand=True, anchor="n", pady=50)

        self.reg_btn = ttk.Button(self.root, text="Sign in", command=self.open_registration)
        self.reg_btn.pack(expand=True, side=RIGHT, padx=100, pady=100, ipadx=10, ipady=10)

        self.auto_btn = ttk.Button(self.root, text="Sign up", command=self.open_authorization)
        self.auto_btn.pack(expand=True, side=LEFT, padx=100, pady=100, ipadx=10, ipady=10)

    def open_registration(self):
        self.root.destroy()
        RegistrationWindow()

    def open_authorization(self):
        self.root.destroy()
        AuthorizationWindow()

    def run(self):
        self.root.mainloop()


class AuthBase:
    def __init__(self):
        self.window = Tk()
        self.window.geometry("600x600")
        self.window.resizable(False, False)
        self.user_db = UserDatabase()
        self.username_entry = None
        self.password_entry = None
        self.message_label = None
        self.init_ui()

    def init_ui(self):
        raise NotImplementedError("Subclasses must implement this method")

    def hash_password(self, password):
        md5_hash = hashlib.new('md5')
        md5_hash.update(password.encode())
        return md5_hash.hexdigest()

    def show_message(self, text):
        if self.message_label:
            self.message_label.destroy()
        self.message_label = Label(self.window, text=text, font=("Arial", 18))
        self.message_label.place(x=150, y=550)

    def run(self):
        self.window.mainloop()


class RegistrationWindow(AuthBase):
    def __init__(self):
        super().__init__()
        self.window.title("Registration")
        self.run()

    def init_ui(self):
        sign_in_label = Label(self.window, text="Sign in", font=("Arial", 24))
        sign_in_label.place(x=240, y=180)

        username_label = Label(self.window, text="Username")
        username_label.place(x=180, y=250)

        password_label = Label(self.window, text="Password")
        password_label.place(x=180, y=300)

        self.username_entry = ttk.Entry(self.window)
        self.username_entry.place(x=250, y=250)

        self.password_entry = ttk.Entry(self.window, show="*")
        self.password_entry.place(x=250, y=300)

        sign_in_btn = ttk.Button(self.window, text="Sign in", command=self.register)
        sign_in_btn.place(x=250, y=400)

    def register(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        if not username or not password:
            self.show_message("Username and password are required!")
            return

        if self.user_db.user_exists(username):
            self.show_message("User already exists!")
            return

        hashed_password = self.hash_password(password)
        self.user_db.add_user(username, hashed_password)
        self.show_message("You registered successfully!")


class AuthorizationWindow(AuthBase):
    def __init__(self):
        super().__init__()
        self.window.title("Authorization")
        self.run()

    def init_ui(self):
        sign_up_label = Label(self.window, text="Sign up", font=("Arial", 24))
        sign_up_label.place(x=240, y=180)

        username_label = Label(self.window, text="Username")
        username_label.place(x=180, y=250)

        password_label = Label(self.window, text="Password")
        password_label.place(x=180, y=300)

        self.username_entry = ttk.Entry(self.window)
        self.username_entry.place(x=250, y=250)

        self.password_entry = ttk.Entry(self.window, show="*")
        self.password_entry.place(x=250, y=300)

        sign_up_btn = ttk.Button(self.window, text="Sign up", command=self.authenticate)
        sign_up_btn.place(x=250, y=400)

    def authenticate(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        if not username or not password:
            self.show_message("Username and password are required!")
            return

        if not self.user_db.user_exists(username):
            self.show_message("User not found!")
            return

        data = self.user_db.load_data()
        hashed_password = self.hash_password(password)

        if data[username] == hashed_password:
            self.show_message("Login successful!")
        else:
            self.show_message("Incorrect password!")


if __name__ == "__main__":
    app = AuthApp()
    app.run()
