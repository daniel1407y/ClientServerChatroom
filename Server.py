import hashlib
import csv
import os
import queue
import socket
import threading
import time
from datetime import datetime

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

HOST = '127.0.0.1' # loopback IP address
PORT = 5000  # listening ports
FORMAT = 'utf-8'  # encoding format
ADDR = (HOST, PORT)  # tuple of IP+PORT

# Generate a key and IV (Initialization Vector)
key = b'\x04\x03|\xeb\x8dSh\xe0\xc5\xae\xe5\xe1l9\x0co\xca\xb1"\r-Oo\xbaiYa\x1e\xd1\xf7\xa2\xdf'
iv = b'#\xb59\xee\xa7\xc4@n\xe5r\xac\x97lV\xff\xf1'
       
class Client:
    def __init__(self, conn):
        self.conn = conn # connection identification
        self.name = ""
        self.chatroom_id = 0
        self.role = "regular"
        self.kicked = 0 # a flag indicating if the user has just been kicked

class Room:
    def __init__(self, room_id, history, admin_name):
        self.room_id = room_id
        self.history = history # holds all the messages sent in the room
        self.admin_name = admin_name    
    

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

# secure hashing algorithm (SHA-256)
def hash_password(password):
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    return hashed_password


# function to check if user matches the database or create new user. runs until correct login info input (including the new created user)
def check_database(conn, addr):
    while True: 
        data = decrypt(conn.recv(1024))
        username, password, login_or_create = data.split(":")
        if login_or_create=="X":
            return "X_clicked", "X_clicked"
        with open('users.csv', 'r') as csvfile:
            reader = csv.DictReader(csvfile)
            users = list(reader)
            print(f"Received data from client {addr} : \"" + username + "\" \"" + password + "\" \"" + login_or_create + "\"")

            password = hash_password(password) # hashes password
            login_info = {'name': username, 'password': password}
            
            user_exists=False
            # create user case
            if (login_or_create=='create'): 
                for entry in users:
                    if entry['name']==username:
                        user_exists = True
                        conn.send(encrypt("user already exists"))
                        break

                if not user_exists:
                    # add the new user to the list
                    new_user = {'name': username, 'password': password, 'role' : 'regular'}
                    password=hash_password(password)
                    users.append(new_user)
                    with open('users.csv', 'w', newline='') as csvfile:
                        fieldnames = ['name', 'password', 'role']
                        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                        writer.writeheader()
                        writer.writerows(users)
                    conn.send(encrypt("user created successfully"))

            # login case
            elif login_or_create == 'login':
                for user in users:
                    if user['name']==login_info['name'] and user['password']==login_info['password']:
                        conn.send(encrypt("authorized"))
                        return username, password
                conn.send(encrypt("wrong user name or password, please try again"))

# fiiling the rooms list, so that we will be able to match between a room and its history
def fill_rooms_list():
    if len(rooms)==0:
        with open('rooms.csv', mode='r', newline='') as file:
            reader = csv.reader(file)
            for row in reader:
                if row:
                    room_id = row[0]
                    room_history  = ""
                    admin_name = row[1]
                    new_room = Room(room_id, room_history, admin_name)
                    rooms.append(new_room)

        for room in rooms: # filling the history attribute of each room
            room_history=""
            with open('chats.csv', mode='r', newline='') as file:
                reader = csv.reader(file)
                for row in reader:
                    if row and row[0] == room.room_id:
                        room_history+=row[1]
            room.history=room_history


# main server function
def handle_client1(current_client: Client, addr):
    conn = current_client.conn
    print('[CLIENT CONNECTED] on address: ', addr)
    
    name, password = check_database(conn, addr)
    if name=="X_clicked" and password=="X_clicked": # X has been clicked in gui
        x_click(conn, addr)
        return
    fill_rooms_list()
    current_client.name = name
    
    # finished part 1: logging in
    # starting part 2: room selection
    
    quit_flag=True
    try:
        # selecting chatroom
        conn.send(encrypt("Please enter chatroom id to join:"))
        chatroom_id = conn.recv(1024)
        chatroom_id=decrypt(chatroom_id)

        current_client.chatroom_id = chatroom_id
        print(f"Received chatroom from client {addr} : {chatroom_id}")

        if chatroom_id not in [room.room_id for room in rooms]: # chatroom doesnt exist
            room=Room(chatroom_id, "", current_client.name) 
            rooms.append(room)
            with open('rooms.csv', mode='a', newline='') as file:
                writer = csv.writer(file)
                writer.writerow([room.room_id, room.admin_name]) # make the first to open the chatroom the admin

        for room_holder in rooms: # finding the current room
                if room_holder.room_id==current_client.chatroom_id:
                    break
        room=room_holder
        
        # part 2 finished
        # starting part 2.5: initial chatroom messages

        display_history(current_client)
        
        # updating role if user is manager, will ease the "ban_user" function later
        with open('users.csv', 'r') as file:
            reader = csv.DictReader(file)
            users = list(reader)
        for user in users:
            if user['name'] == current_client.name and user['role'] == 'manager':
                current_client.role = 'manager'
                break

        for client in clients: # send a message to all clients in the room if a new client has joined the room
            if client.chatroom_id==current_client.chatroom_id and not client.name==current_client.name:
                join_message = f"{name} has joined the chatroom"
                client.conn.send(encrypt(join_message))
                
        # finished part 2.5
        # starting part 3: chatroom itself
                
        # infinite reading and sending messages/commands loop, with message limit
        message_limit = 5
        time_limit=10
        message_count=0
        start_time=0
        message_queue=queue.Queue()
        while True:
            message = conn.recv(1024)
            message = decrypt(message)
            if current_client.kicked==1: # user was just kicked
                room = work_on_kicked_user(conn, addr, client, message, room)
                message = conn.recv(1024)
                message = decrypt(message)

            current_time = time.time()
            elapsed_time = current_time - start_time
            if elapsed_time > time_limit: # reset message_count
                start_time = current_time
                message_count = 0
                
            if message_count<message_limit:
                print(f"room {current_client.chatroom_id} : Received Message/Command from client {addr} : \"" + message + "\"")
                if message.startswith('/change '): ## request to change chat room
                    room = change_room_request(conn, addr, current_client, message, room)
                elif message == "/quit": ## request to quit chatroomy
                    quit_request(conn, addr, current_client)
                    quit_flag=True
                elif message == "/active": ## request to display active users
                    active_users_request(conn, addr, current_client)
                elif message.startswith('/ban_user '): ## request to ban, only managers can ban
                    ban_request(conn, addr, current_client, message)
                elif message.startswith('/change_pass '): # request to change password
                    change_password(conn, addr, current_client, message)
                elif message.startswith('/kick_user '): ## request to kick a user, only room creators can delete
                    kick_user(conn, addr, current_client, message, room)
                elif message == "delete_chat": ## request to delete chat users, only room creators can delete
                    delete_chat(conn, addr, current_client, message, room)
                elif message.startswith('/receive_file '):  # client wants to receive a file
                    receive_file(conn, message)
                elif message.startswith('/send_file '): # client wants to send a file
                    send_file(conn, message)

                else: # normal message, send to clients in the room and add to room history
                    time_message = datetime.now().strftime("%d-%m-%y %H:%M:%S")
                    for client in clients:
                        if client.chatroom_id == current_client.chatroom_id:
                            echo_message = f"[{time_message}] {name} : {message}"
                            client.conn.send(encrypt(echo_message))
                            
                    for room_holder in rooms: # adding message to current room history
                        if (room_holder.room_id == current_client.chatroom_id):
                            room_holder.history += (f"[{time_message}] {current_client.name} : {message}\n") # add the message to the history of the room
                            with open('chats.csv', mode='a', newline='') as file:
                                writer = csv.writer(file)
                                writer.writerow([current_client.chatroom_id, f"[{time_message}] {current_client.name} : {message}\n", room_holder.admin_name])

                message_count+=1
            else: ## limit reached
                limit_message = f"[SERVER MESSAGE :Message limit reached\nPlease wait {int(time_limit-elapsed_time)} more seconds]"
                current_client.conn.send(encrypt(limit_message))
                message_queue.put(message)
                while not message_queue.empty():
                    message_queue.get_nowait()

    except:
        if quit_flag:
            clients.remove(current_client)
            return
        print("[CLIENT CONNECTION INTERRUPTED] on address: ", addr)
        clients.remove(current_client)
        return




def x_click(conn, addr): # x click on some gui
    print("[CLIENT DISCONNECTED] on address: ", addr)
    conn.send(encrypt("disconnect"))
    #conn.close()
    return
    
    
    
# send_message was requested, send the file from client to server.files directory
def send_file(conn, message):
    file_path = message[len('/send_file '):].strip()

    file_name = os.path.basename(file_path)
    destination_folder = "server_files/"
    destination_path = os.path.join(destination_folder, file_name)

    base_name, file_extension = os.path.splitext(file_name)
    counter= 1
    while os.path.exists(destination_path):
        # file already exists, update the counter inside the parentheses
        file_name = f"{base_name}({counter}){file_extension}"
        destination_path = os.path.join(destination_folder, file_name)
        counter+= 1

    if os.path.exists(file_path): # read from one file and write to another
        with open(file_path, 'rb') as original_file:
            with open(destination_path, 'wb') as new_file:
                line = original_file.read(1024)
                while line:
                    new_file.write(line)
                    line = original_file.read(1024)
        conn.send(encrypt(f"[SERVER MESSAGE : {file_name} has been successfuly sent]"))
    else:
        print(f"[SERVER MESSAGE : The file '{file_name}' does not exist in the source folder]")
        conn.send(encrypt(f"[SERVER MESSAGE : The file '{file_name}' does not exist in the source folder]"))




# receive_file was requested, receive the files from server.files
def receive_file(conn, message):
    file_name = message[len('/receive_file '):].strip()
                
    destination_folder=os.getcwd() # current folder
    base_name, file_extension = os.path.splitext(file_name)
    destination_path = os.path.join(destination_folder, file_name)
    
    source_directory = "server_files"
    file_path = os.path.join(source_directory, file_name)
    if not os.path.isfile(file_path): # checking if file in server_files directory
        print(f"[Server Message] : The file '{file_name}' does not exist in the source folder.")
        conn.send(encrypt(f"[SERVER MESSAGE : The file '{file_name}' does not exist in the source folder]"))
    else:
        counter = 1
        original_file_name = file_name
        while os.path.exists(destination_path):
        # if the file exists, increment the counter and modify the file_name
            counter += 1
            file_name = f"{base_name}({counter}){file_extension}"
            destination_path = os.path.join(destination_folder, file_name)
            
        with open(f"server_files/{original_file_name}", 'rb') as original_file: # read from one file and write to another
            with open(file_name, 'wb') as new_file:
                line = original_file.read(1024)
                while line:
                    new_file.write(line)
                    line = original_file.read(1024)     
        conn.send(encrypt(f"[SERVER MESSAGE : {file_name} has been successfuly sent]"))   





# delete the cuurent chatroom
def delete_chat(conn, addr, current_client, message, room:Room):
    if current_client.name==room.admin_name: # only admin can delete the room
        for client in clients:
            if client.chatroom_id==room.room_id:
                client.conn.send(encrypt("[SERVER MESSAGE : The chat has been deleted]"))
                client.conn.send(encrypt("[SERVER MESSAGE : please write /change X, with X representing new chat, or /quit to quit]"))
                client.kicked=1 # everyone must choose a new room or quit
        rooms.remove(room)
    else:
        current_client.conn.send(encrypt("[SERVER MESSAGE : not admin]"))

    # must update chats.csv and rooms.csv
    new_rows = []
    with open('chats.csv', 'r', newline='') as csvfile: # remove all instances from chats
        reader = csv.reader(csvfile)  
        for row in reader:
            if row and not row[0] == room.room_id:
                new_rows.append(row)
    with open('chats.csv', 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerows(new_rows)

    new_rows = []
    with open('rooms.csv', 'r', newline='') as csvfile: # remove all instances from rooms
        reader = csv.reader(csvfile)  
        for row in reader:
            if row and not row[0] == room.room_id:
                new_rows.append(row)
    with open('rooms.csv', 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerows(new_rows)

            

# kick user from the current chatroom request
def kick_user(conn:socket.socket, addr, current_client:Client, message, room:Room):
    kicked_user = message[len('/kick_user '):].strip()

    if current_client.name==room.admin_name: ## only an admin of the room can kick
        with open('users.csv', 'r') as file:
            reader = csv.DictReader(file)
            users = list(reader)
        kicked_user_name= None
        for user in users: # finding the banned user's name, if it even exists
                    if user['name'] == kicked_user:
                        kicked_user_name = user['name']
                        break
        if kicked_user_name: # user in current chat
            for client in clients:
                in_chat=False
                if client.name==kicked_user_name:
                    if client.chatroom_id==room.room_id:
                        client.conn.send(encrypt("[SERVER MESSAGE : you have been kicked/Chatroom deleted]"))
                        client.conn.send(encrypt("[SERVER MESSAGE : please write /change X, with X representing a new chat, or /quit to quit]"))
                        client.kicked=1 # "kicked status" is 1, meaning it cant send messages to the current chat right now
                        in_chat=True
                        break
                    
            if in_chat==False:
                conn.send(encrypt(f"[SERVER MESSAGE : user not in current chat]"))  
        else: # user not in current chat
            conn.send(encrypt(f"[SERVER MESSAGE : user not in current chat]"))
    else: ## not admin
        conn.send(encrypt(f"[SERVER MESSAGE : not an admin]"))


# kicked user can only input 2 messages: quit or change room, after which we change his 'kicked' attribute to 0
def work_on_kicked_user(conn, addr, client: Client, message, room:Room):
    message_queue=queue.Queue()
    new_chatroom = message[len('/change '):].strip()
    while True:
        if message=="/quit" or (message.startswith('/change ') and not client.chatroom_id==new_chatroom):
            break
        message_queue.put(message)
        message = client.conn.recv(1024)
        message = decrypt(message)
        
        new_chatroom = message[len('/change '):].strip()
    while not message_queue.empty():
            message_queue.get_nowait()
    if message=="/quit":
        quit_request(client.conn, addr, client)
    else:
        room = change_room_request(conn, addr, client, message, room)
    client.kicked = 0
    return room


def display_history(current_client:Client):
    with open('chats.csv', mode='r', newline='') as file: # room exists, read from chats.csv the history
            reader = csv.reader(file)
            past_messages = ""
            for row in reader:
                if row and row[0] == current_client.chatroom_id: # row 0 : room id
                    past_messages+=row[1] # row 1 : client and his message
    
            for room in rooms: # send the history retreived to the room
                if room.room_id==current_client.chatroom_id:
                    # sometimes the messages get stuck because "past_messages" is long, so we time.sleep a bit to avoid crashing
                    message = "************************************"
                    current_client.conn.send(encrypt(message))
                    time.sleep(0.02)
                    current_client.conn.send(encrypt("Past Messages:"))
                    time.sleep(0.02)
                    current_client.conn.send(encrypt(past_messages))
                    time.sleep(0.02)
                    current_client.conn.send(encrypt("************************************\n"))
                    time.sleep(0.02)
                    past_messages=""
                    break


def change_password(conn, addr, current_client, message):
    with open('users.csv', 'r') as file:
            reader = csv.DictReader(file)
            users = list(reader)
    for user in users:
        if user['name'] == current_client.name:
            matching_user = user
            break

    #updating password in the csv file
    new_password = message[len('/change_pass '):].strip()
    new_password = hash_password(new_password)
    matching_user['password'] = new_password
    with open('users.csv', 'w', newline='') as write_file:
        fieldnames = ['name', 'password', 'role']
        writer = csv.DictWriter(write_file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(users)
    print(f"Password changed for user: {matching_user['name']}")
    current_client.conn.send(encrypt("[SERVER MESSAGE : password successfuly changed]"))


# display active users command was requested
def active_users_request(conn, addr, current_client):
    current_client.conn.send(encrypt("[SERVER MESSAGE : Active Users:"))
    for client in clients:
        current_client.conn.send(encrypt(f"{client.name} : {client.role}. In chat \"{client.chatroom_id}\""))
    conn.send(encrypt("]"))


# ban a user command was requested
def ban_request(conn, addr, current_client:Client, message):
    if current_client.role=='manager':
        banned_user = message[len('/ban_user '):].strip()
        with open('users.csv', 'r') as file:
            reader = csv.DictReader(file)
            users = list(reader)

        banned_user_name= None
        for user in users: # finding the banned user's name
            if user['name'] == banned_user:
                banned_user_name = user['name']
                break

        if banned_user_name: # if it indeed exist in the database:
            updated_users = [user for user in users if user['name'] != banned_user] ## users without the banned user
            with open('users.csv', 'w', newline='') as file:
                fieldnames = ['name', 'password', 'role']
                writer = csv.DictWriter(file, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(updated_users)

            for user in users: ## banning message gets sent only to manager
                if user['role']=="manager":
                    conn.send(encrypt(f"[SERVER MESSAGE : {banned_user_name} has been banned]"))
            for client in clients: # ban message itself to banned user
                if client.name==banned_user_name:
                    client.conn.send(encrypt("[SERVER MESSAGE : you have been banned]"))

        else: # user not in database
            conn.send(encrypt(f"[SERVER MESSAGE : user not in database]"))
    else: ## not manager
        conn.send(encrypt(f"[SERVER MESSAGE : not an manager]"))
    


# change_X command was requested (change room)
def change_room_request(conn, addr, current_client:Client, message, room:Room):
    current_chatroom = current_client.chatroom_id
    new_chatroom = message[len('/change '):].strip()
    if current_chatroom==new_chatroom: ## same room 
        same_room_message=f"[SERVER MESSAGE : ALREADY IN CHATROOM {new_chatroom}]"
        current_client.conn.send(encrypt(same_room_message))
        return room # return the current room
    else:
        for client in clients:
            if client.chatroom_id==current_chatroom and client.conn!=current_client.conn: ## all clients in old chatroom except source get this message
                client.conn.send(encrypt(f"{current_client.name} has left the chatroom"))
            elif client.chatroom_id==new_chatroom: ## all clients in new chatroom get this message
                client.conn.send(encrypt(f"{current_client.name} joined the room"))
        current_client.conn.send(encrypt(f"leaving room {client.chatroom_id}... joining room {new_chatroom}"))
        current_client.chatroom_id = new_chatroom ## update client's chatroom

        if new_chatroom not in [room_holder.room_id for room_holder in rooms]: # room doesnt exist
            room=Room(new_chatroom, "", current_client.name)
            rooms.append(room)

            # adding to rooms.csv
            with open('rooms.csv', mode='a', newline='') as file:
                writer = csv.writer(file)
                writer.writerow([room.room_id, room.admin_name])
        else: # room exists already
            for room in rooms:
                if room.room_id==new_chatroom:
                    break
        display_history(current_client)
        return room
                
            

# quit command was requested
def quit_request(conn, addr, current_client: Client):
        current_chatroom = current_client.chatroom_id
        #clients.remove(current_client)
        for client in clients:
            if client.chatroom_id==current_chatroom: # only send to clients in the same chatroom
                    client.conn.send(encrypt(f"{current_client.name} has disconnected from the server"))
        print("[CLIENT DISCONNECTED] on address: ", addr)



def start_server():
    server_socket.bind(ADDR)
    print(f"[LISTENING] server is listening on {HOST}")
    server_socket.listen()
    while True:
        print(f"[ACTIVE CONNECTIONS] {threading.active_count() - 1}\n")
        connection, address = server_socket.accept()  # Waiting for client to connect to server (blocking call)
        new_client = Client(connection)
        clients.append(new_client)

        thread = threading.Thread(target=handle_client1, args=(new_client, address))
        thread.start()


if __name__ == '__main__':
    clients :list[Client] = []
    rooms :list[Room]= []
    IP = socket.gethostbyname(socket.gethostname())  # finding your current IP address
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Opening Server socket
    print("[STARTING] server is starting...")
    start_server()
    print("THE END!")

