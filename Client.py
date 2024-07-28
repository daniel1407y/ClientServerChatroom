import socket
import threading
import time
from tkinter import *

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

from ctypes import windll
windll.shcore.SetProcessDpiAwareness(1) # makes gui not blurry

HOST = '127.0.0.1'  # server's hostname or IP address
PORT = 5000  # port used by the server
FORMAT = 'utf-8' # encoding format
ADDR = (HOST, PORT)  # tuple of IP+PORT

# Generate a key and IV (Initialization Vector)
key = b'\x04\x03|\xeb\x8dSh\xe0\xc5\xae\xe5\xe1l9\x0co\xca\xb1"\r-Oo\xbaiYa\x1e\xd1\xf7\xa2\xdf'
iv = b'#\xb59\xee\xa7\xc4@n\xe5r\xac\x97lV\xff\xf1'

# Function to encrypt plaintext using AES-CBC
def encrypt(plaintext):
    time.sleep(0.05)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode(FORMAT)) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return ciphertext

# Function to decrypt ciphertext using AES-CBC
def decrypt(ciphertext):
    time.sleep(0.05)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()
    return decrypted_data.decode(FORMAT)




def start_client():
        client_socket.connect((HOST, PORT))  # Connecting to server's socket
        notFirstEntry=False
        while True:
            if notFirstEntry:
                popup_window(message)
            login_info = LoginWindow() # from gui
            login_info = LoginWindow.get_login_info(login_info)
            username = login_info['name']
            password = login_info['password']
            login_or_create = login_info['login_or_create']
            if username=="" or password=="":
                notFirstEntry=True
                continue
            
            data = f"{username}:{password}:{login_or_create}"
            print("[CLIENT] sent data: ", data)
            client_socket.send(encrypt(data))
            message = client_socket.recv(1024)
            message = decrypt(message)
            print(message)
            if message =="authorized": # server checks database, if user exists/if password matches/ if create new user
                break
            elif message=="disconnect":
                print("YOU HAVE DISCONNECTED FROM THE SERVER")
                client_socket.close()
                return
            else:
                notFirstEntry=True
        ## finished part 1: logging in
            
        ## starting part 2: chatroom selection
        select_room_message = client_socket.recv(1024)
        select_room_message = decrypt(select_room_message)
        print(select_room_message)
        
        option = RoomSelection() # second gui, room selection
        selected_option  = RoomSelection.get_selected_room(option)
        
        print("selected room : ", selected_option)
        client_socket.send(encrypt(selected_option))

        ## part 3: chatroom itself
        Chatroom(selected_option, client_socket)
        time.sleep(1) # waiting a bit for server to complete his quit_request function in order to correctly disconnect
        client_socket.close()
        print("YOU HAVE DISCONNECTED FROM THE SERVER")


# popup window in case user created / wrong log in provided / user already exists
class popup_window:
    def __init__(self, message):
        self.message = message
        self.create_window()
        
    def create_window(self):
        self.window = Tk()
        self.window.configure(bg="lightblue2")
        self.window.title("Error Message")
        lbl_name = Label(text=self.message, background="lightblue2", font=("Arial Bold", 10))
        confirm_button = Button(self.window, text="Confirm", command=self.window.destroy, bg="lightgray")
        lbl_name.grid(row=0, column=0, padx=30, pady=10)
        confirm_button.grid(row=1, padx=10, pady=20)        
        self.window.mainloop()
        



# login window gui
class LoginWindow:
    def __init__(self):
        self.info = {'name': None, 'password': None, 'login_or_create': None}
        self.create_window()

    def info_login(self):
        self.info['name'] = self.entry_name.get()
        self.info['password'] = self.entry_password.get()
        self.info['login_or_create'] = 'login'
        self.window.destroy()

    def on_close(self):
        self.info['name'] = 'X'
        self.info['password'] = 'X'
        self.info['login_or_create'] = 'X'
        self.window.destroy()

    def create(self):
        signup_window= Tk()
        signup_window.title("Sign Up")
        signup_window.configure(bg="lightblue2")
        
        lbl_new_username= Label(signup_window, text="New Username", bg="lightblue2")
        entry_new_username= Entry(signup_window, width=30)
        lbl_new_password= Label(signup_window, text="New Password", bg="lightblue2")
        entry_new_password= Entry(signup_window, width=30, show="*")

        def info_create():
            self.info['name'] = entry_new_username.get()
            self.info['password'] = entry_new_password.get()
            self.info['login_or_create'] = 'create'
            signup_window.destroy()
            self.window.destroy()

        signup_button = Button(signup_window, text="Sign Up", command=info_create, bg="lightgray")

        lbl_new_username.grid(row=0, column=0, sticky=E, padx=7, pady=10)
        entry_new_username.grid(row=0, column=1, pady=5, padx=10)
        lbl_new_password.grid(row=1, column=0, sticky=E, padx=7)
        entry_new_password.grid(row=1, column=1, pady=5, padx=10)
        signup_button.grid(row=2, column=1, pady=10)

        signup_window.mainloop()

    def create_window(self):
        self.window= Tk()
        self.window.title("The Chatrooms")
        self.window.configure(bg="lightblue2")
        self.window.protocol("WM_DELETE_WINDOW", self.on_close)  # bind window closing event

        lbl_welcome = Label(self.window, text="Welcome to \"THE CHATROOMS\"", font=("Arial Bold", 20), bg="lightblue2")
        lbl_login = Label(self.window, text="please log in below ", font=("Arial Bold", 10), bg="lightblue2")
        lbl_welcome.pack()
        lbl_login.pack()
        
        inputs_frame = Frame(self.window)
        inputs_frame.configure(bg="lightblue2")
        inputs_frame.pack(fill=BOTH, expand=True)
        lbl_name = Label(inputs_frame, text="username", background="lightblue2")
        self.entry_name = Entry(inputs_frame, width=30)
        lbl_password = Label(inputs_frame, text="password ", bg="lightblue2")
        self.entry_password = Entry(inputs_frame, width=30, show="*")
        login_button = Button(self.window, text="Login", command=self.info_login, bg="lightgray")
        create_button = Button(self.window, text="Sign Up", command=self.create, bg="lightgray")


        lbl_name.grid(row=0, column=0, sticky=E)
        self.entry_name.grid(row=0, column=1, pady=5)
        lbl_password.grid(row=1, column=0, sticky=E)
        self.entry_password.grid(row=1, column=1, pady=5)
        login_button.pack(pady=8)
        create_button.pack(pady=10)
        # centers the columns in the inputs_frame
        inputs_frame.columnconfigure(0, weight=1)
        inputs_frame.columnconfigure(1, weight=1)

        self.window.mainloop()

    def get_login_info(self):
        return self.info



#chatroom selection gui
class RoomSelection:
    def __init__(self):
        self.result = {'selected_room': None}
        self.create_window()

    def on_close(self):
        self.result['selected_room'] = "X_has_been_selected"
        print("laalala")
        self.window.destroy()

    def room_selection(self):
        self.result['selected_room'] = self.room_number_entry.get()
        self.window.destroy()

    def create_window(self):
        self.window= Tk()
        self.window.title("Room Selection")
        self.window.protocol("WM_DELETE_WINDOW", self.on_close)  # bind window closing event

        self.window.configure(bg="lightblue2")
        lbl_lobby = Label(self.window, text="Room Selection", font=("Arial Bold", 10), bg="lightblue2")
        lbl_lobby2 = Label(self.window, text="Main Please enter room number", font=("Arial", 8), bg="lightblue2")

        self.room_number_entry = Entry(self.window, width=30)
        join_room_button = Button(self.window, text="Join Room", command=self.room_selection, bg="lightgray")

        lbl_lobby.pack()
        lbl_lobby2.pack()
        self.room_number_entry.pack(padx=20)
        join_room_button.pack(padx=5, pady=20)

        self.window.mainloop()

    def get_selected_room(self):
        return self.result['selected_room']








# main chatroom gui, where all the messages are sent
class Chatroom:
    def __init__(self, selected_room, client_socket: socket.socket):
        self.selected_room = selected_room
        self.create_window()
        #self.client_socket = client_socket
        client_socket.setblocking(False)

    def update_chat_display(self, message):
        self.chat_display.config(state=NORMAL)
        self.chat_display.insert(END, message + "\n")
        self.chat_display.config(state=DISABLED)
        self.chat_display.see(END)

    def receive_messages(self): # a thread which constantly reads messages from the server and prints them
        while True:
            try:
                message = client_socket.recv(1024)
                message = decrypt(message)
                if message:
                    if message=="[SERVER MESSAGE : you have been banned]":
                        print(message)
                        self.on_close()
                    self.update_chat_display(message)
            except socket.error:
                pass

    def send_message(self): # sending messages to server
            message = self.message_entry.get()
            client_socket.send(encrypt(message))
            if message=="/quit":
                self.on_close()

    def on_close(self):
        self.window.destroy()

    def create_window(self):
        self.window = Tk()
        self.window.title("Chatroom")
        self.window.configure(bg="lightblue2")
        self.window.protocol("WM_DELETE_WINDOW", self.on_close)  # bind window closing event

        self.chat_display = Text(self.window, width=50, height=20, wrap="word", state=DISABLED, bg="azure")
        self.scrollbar = Scrollbar(self.window, command=self.chat_display.yview)
        self.chat_display.config(yscrollcommand=self.scrollbar.set)
        self.message_entry = Entry(self.window, width=30)
        send_button = Button(self.window, text="Send", command=self.send_message, bg="lightgray")
        
        self.scrollbar.pack(side="right", fill="y")
        self.chat_display.pack(padx=5, pady=5)
        self.message_entry.pack(pady=5)
        send_button.pack(padx=5, pady=5)

        self.receive_thread = threading.Thread(target=self.receive_messages, daemon=True)
        self.receive_thread.start()
        self.window.mainloop()



if __name__ == "__main__":
    IP = socket.gethostbyname(socket.gethostname())
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    print("[CLIENT] Started running")
    start_client()
    print("Goodbye :)")