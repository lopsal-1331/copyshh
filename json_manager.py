import json
import base64
import os 

class Json:
    @staticmethod
    def store_data(user:str, token:bytes, salt:bytes):
        # function to store user data into the global server database
        from encryption import Encryption 
        print(user, token, token.decode(), salt)
        # create the json diccionary
        user_data={
            'username':user, 
            'token':base64.urlsafe_b64encode(token).decode(), 
            'salt': base64.urlsafe_b64encode(salt).decode()
        }
        # encrypt the entry using the database secret fernet key
        encrypted_data=Encryption.encrypt_fernet(json.dumps(user_data)).decode()
        # try and open database to load the user's data
        try:
            with open("global_server/database.json", 'r') as file:
                try:
                    content = json.load(file)
                except json.JSONDecodeError:
                    print("Warning: file is empty or contains invalid JSON. Initializing with an empty list.")
                    content = []
        except FileNotFoundError:
            print("File  not found. Creating a new one.")
            content = []
        content.append(encrypted_data)
        with open("global_server/database.json", 'w') as file:
            json.dump(content, file, indent=4)

    @staticmethod
    def get_user_data(username: str):
        # function to get a user data from the global server database
        from encryption import Encryption
        # try and load data from the global_server database
        try:
            with open("global_server/database.json", 'r') as file:
                try:
                    content = json.load(file)
                except json.JSONDecodeError:
                    print("Warning: file is empty or contains invalid JSON.")
                    return None
        except FileNotFoundError:
            print("File not found.")
            return None
        # for each entry in the list of json diccionaries
        for entry in content:
            try:
                # Decrypt the entry
                decrypted_entry = Encryption.decrypt_fernet(entry)
                user_data = json.loads(decrypted_entry)
                # search for the username
                if user_data['username'] == username:
                    user_data['token'] = base64.urlsafe_b64decode(user_data['token'])
                    user_data['salt'] = base64.urlsafe_b64decode(user_data['salt'])
                    # only returns the entry of the username, but the database is always encrypted
                    return user_data  
                
            except Exception as e:
                print(f"Error decrypting data for entry: {e}")
                print("Entry that caused the error:", entry) 
                continue  

        print("User not found.")
        return None  
    
    @staticmethod
    def save_to_file(file_path, data):
        #function to save data into a file
        with open(file_path, 'wb') as f:
            f.write(data)
    
    @staticmethod
    def read_from_file(file_path):
        # function to read data from a json
        with open(file_path, 'rb') as f:
            return f.read()

    @staticmethod
    def find_files_with_suffix(directory, suffix):
        # function to find files which filename's end in an specifit suffix
        found_files = []
        for filename in os.listdir(directory):
            if filename.endswith(suffix):
                found_files.append(filename)
        return found_files

    @staticmethod
    def append_to_file(filepath, message):
        # Method to append an entry to a list of json diccionaries
        data=[]
        if os.path.exists(filepath): 
            with open(filepath, 'r') as file: 
                try: 
                    data=json.load(file)
                except json.JSONDecodeError:
                    data=[]
        data.append(message)
        with open(filepath, 'w')as file: 
            json.dump(data, file)
    
    @staticmethod
    def read_from_json(filepath):
        # function to read from a json file in format [{}{}]
        if os.path.exists(filepath):
            with open(filepath, 'r') as file:
                try:
                    return json.load(file)
                except json.JSONDecodeError:
                    return []
        return []

    @staticmethod
    def clear_file(filepath):
        # function to clear a file --> used to clear message already delivered to receiver
        with open(filepath, 'w') as file:
            json.dump([], file)

    