from cryptography.fernet import Fernet
import os
from pathlib import Path
from datetime import datetime

class FileCrypto:
    def __init__(self):
        self.upload_folder = Path('uploads')
        self.upload_folder.mkdir(exist_ok=True)

    def _generate_key(self):
        return Fernet.generate_key()

    def _save_file(self, file):
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        filename = f"{timestamp}_{file.filename}"
        file_path = self.upload_folder / filename
        file.save(file_path)
        return file_path

    def encrypt(self, file):
        key = self._generate_key()
        fernet = Fernet(key)
        file_path = self._save_file(file)
        
        with open(file_path, 'rb') as f:
            data = f.read()
        
        encrypted = fernet.encrypt(data)
        encrypted_path = file_path.with_suffix('.encrypted')
        
        with open(encrypted_path, 'wb') as f:
            f.write(encrypted)
        
        os.remove(file_path)
        return key, encrypted_path.name

    def decrypt(self, file, key):
        file_path = self._save_file(file)
        
        with open(file_path, 'rb') as f:
            data = f.read()
        
        fernet = Fernet(key)
        decrypted = fernet.decrypt(data)
        
        original_filename = file.filename.replace('.encrypted', '')
        decrypted_path = self.upload_folder / original_filename
        
        with open(decrypted_path, 'wb') as f:
            f.write(decrypted)
        
        os.remove(file_path)
        return decrypted_path
