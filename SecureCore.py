"""
SecureCore - Military-grade folder encryption with auto-destruct capabilities.

Author: LMLK-seal
License: MIT
Version: 1.3.1
"""

import customtkinter as ctk
import tkinter as tk
from tkinter import filedialog, messagebox
import os
import json
import hashlib
import secrets
import threading
import time
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.backends import default_backend
import shutil
import zipfile
import tempfile
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('folder_security.log'),
        logging.StreamHandler()
    ]
)

class SecureFolderManager:
    def __init__(self):
        self.backend = default_backend()
        self.config_file = "secure_folders.json"
        self.load_config()
        
    def load_config(self):
        """Load configuration of secured folders"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    self.secured_folders = json.load(f)
            else:
                self.secured_folders = {}
        except Exception as e:
            logging.error(f"Error loading config: {e}")
            self.secured_folders = {}
    
    def save_config(self):
        """Save configuration of secured folders"""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.secured_folders, f, indent=2)
        except Exception as e:
            logging.error(f"Error saving config: {e}")
    
    def derive_key(self, password: str, salt: bytes) -> bytes:
        """Derive encryption key from password using PBKDF2"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # 256-bit key
            salt=salt,
            iterations=100000,  # Strong iteration count
            backend=self.backend
        )
        return kdf.derive(password.encode())
    
    def encrypt_data(self, data: bytes, password: str) -> bytes:
        """Encrypt data using AES-256-CBC"""
        salt = secrets.token_bytes(16)
        key = self.derive_key(password, salt)
        iv = secrets.token_bytes(16)
        
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        
        # Add PKCS7 padding
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()
        
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        
        # Return salt + iv + encrypted_data
        return salt + iv + encrypted_data
    
    def decrypt_data(self, encrypted_data: bytes, password: str) -> bytes:
        """Decrypt data using AES-256-CBC"""
        salt = encrypted_data[:16]
        iv = encrypted_data[16:32]
        ciphertext = encrypted_data[32:]
        
        key = self.derive_key(password, salt)
        
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
        decryptor = cipher.decryptor()
        
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Remove PKCS7 padding
        unpadder = padding.PKCS7(128).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()
        
        return data
    
    def gutmann_secure_delete(self, file_path: str):
        """Implement Gutmann secure deletion method (35-pass overwrite)"""
        if not os.path.exists(file_path):
            return
        
        try:
            file_size = os.path.getsize(file_path)
            
            # Gutmann's 35-pass pattern
            patterns = [
                # Random passes
                lambda: secrets.token_bytes(1024),
                lambda: secrets.token_bytes(1024),
                lambda: secrets.token_bytes(1024),
                lambda: secrets.token_bytes(1024),
                # Specific patterns (simplified version)
                lambda: b'\x55' * 1024,  # 01010101
                lambda: b'\xAA' * 1024,  # 10101010
                lambda: b'\x92\x49\x24' * 342,  # 10010010 01001001 00100100
                lambda: b'\x49\x24\x92' * 342,  # 01001001 00100100 10010010
                lambda: b'\x24\x92\x49' * 342,  # 00100100 10010010 01001001
                lambda: b'\x00' * 1024,  # All zeros
                lambda: b'\x11' * 1024,  # 00010001
                lambda: b'\x22' * 1024,  # 00100010
                lambda: b'\x33' * 1024,  # 00110011
                lambda: b'\x44' * 1024,  # 01000100
                lambda: b'\x55' * 1024,  # 01010101
                lambda: b'\x66' * 1024,  # 01100110
                lambda: b'\x77' * 1024,  # 01110111
                lambda: b'\x88' * 1024,  # 10001000
                lambda: b'\x99' * 1024,  # 10011001
                lambda: b'\xAA' * 1024,  # 10101010
                lambda: b'\xBB' * 1024,  # 10111011
                lambda: b'\xCC' * 1024,  # 11001100
                lambda: b'\xDD' * 1024,  # 11011101
                lambda: b'\xEE' * 1024,  # 11101110
                lambda: b'\xFF' * 1024,  # 11111111
                lambda: b'\x92\x49\x24' * 342,
                lambda: b'\x49\x24\x92' * 342,
                lambda: b'\x24\x92\x49' * 342,
                lambda: b'\x6D\xB6\xDB' * 342,
                lambda: b'\xB6\xDB\x6D' * 342,
                lambda: b'\xDB\x6D\xB6' * 342,
                # Final random passes
                lambda: secrets.token_bytes(1024),
                lambda: secrets.token_bytes(1024),
                lambda: secrets.token_bytes(1024),
                lambda: secrets.token_bytes(1024),
                lambda: secrets.token_bytes(1024),
                lambda: secrets.token_bytes(1024)
            ]
            
            with open(file_path, 'r+b') as f:
                for i, pattern_func in enumerate(patterns):
                    f.seek(0)
                    remaining = file_size
                    
                    while remaining > 0:
                        pattern = pattern_func()
                        chunk_size = min(len(pattern), remaining)
                        f.write(pattern[:chunk_size])
                        remaining -= chunk_size
                    
                    f.flush()
                    os.fsync(f.fileno())
            
            os.remove(file_path)
            logging.info(f"Gutmann secure deletion completed for: {file_path}")
            
        except Exception as e:
            logging.error(f"Error in Gutmann deletion: {e}")
    
    def secure_delete_folder(self, folder_path: str):
        """Securely delete entire folder using Gutmann method"""
        if not os.path.exists(folder_path):
            return
        
        try:
            # Recursively delete all files
            for root, dirs, files in os.walk(folder_path, topdown=False):
                for file in files:
                    file_path = os.path.join(root, file)
                    self.gutmann_secure_delete(file_path)
                
                for dir in dirs:
                    dir_path = os.path.join(root, dir)
                    try:
                        os.rmdir(dir_path)
                    except:
                        pass
            
            # Remove the main folder
            try:
                os.rmdir(folder_path)
            except:
                shutil.rmtree(folder_path, ignore_errors=True)
            
            logging.info(f"Secure folder deletion completed: {folder_path}")
            
        except Exception as e:
            logging.error(f"Error in secure folder deletion: {e}")
    
    def encrypt_folder(self, folder_path: str, password: str) -> str:
        """Encrypt entire folder and create encrypted archive"""
        temp_zip_path = None
        try:
            # Create temporary zip file with better handling
            temp_zip = tempfile.NamedTemporaryFile(suffix='.zip', delete=False)
            temp_zip_path = temp_zip.name
            temp_zip.close()  # Close the file handle immediately
            
            # Compress folder to zip
            with zipfile.ZipFile(temp_zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for root, dirs, files in os.walk(folder_path):
                    for file in files:
                        file_path = os.path.join(root, file)
                        arcname = os.path.relpath(file_path, folder_path)
                        zipf.write(file_path, arcname)
            
            # Read zip data
            with open(temp_zip_path, 'rb') as f:
                zip_data = f.read()
            
            # Encrypt zip data
            encrypted_data = self.encrypt_data(zip_data, password)
            
            # Create encrypted file
            encrypted_file_path = folder_path + '.secure'
            with open(encrypted_file_path, 'wb') as f:
                f.write(encrypted_data)
            
            # Force garbage collection to release file handles
            import gc
            gc.collect()
            
            # Wait a moment for Windows to release file handles
            time.sleep(0.1)
            
            # Securely delete original folder
            self.secure_delete_folder(folder_path)
            
            return encrypted_file_path
            
        except Exception as e:
            logging.error(f"Error encrypting folder: {e}")
            raise
        finally:
            # Clean up temp file with retry mechanism
            if temp_zip_path and os.path.exists(temp_zip_path):
                max_retries = 5
                for attempt in range(max_retries):
                    try:
                        os.unlink(temp_zip_path)
                        logging.info("Temporary encryption file cleaned up successfully")
                        break
                    except PermissionError as e:
                        if attempt < max_retries - 1:
                            logging.warning(f"Attempt {attempt + 1}: Could not delete temp file, retrying in 0.5 seconds...")
                            time.sleep(0.5)
                        else:
                            logging.warning(f"Could not delete temporary file after {max_retries} attempts: {temp_zip_path}")
                    except Exception as e:
                        logging.warning(f"Unexpected error cleaning up temp file: {e}")
                        break
    
    def decrypt_folder(self, encrypted_file_path: str, password: str, output_path: str):
        """Decrypt folder from encrypted archive"""
        temp_zip_path = None
        try:
            # Read encrypted data
            with open(encrypted_file_path, 'rb') as f:
                encrypted_data = f.read()
            
            # Decrypt data
            zip_data = self.decrypt_data(encrypted_data, password)
            
            # Create temporary zip file with better handling
            temp_zip = tempfile.NamedTemporaryFile(suffix='.zip', delete=False)
            temp_zip_path = temp_zip.name
            temp_zip.close()  # Close the file handle immediately
            
            # Write decrypted data to temp file
            with open(temp_zip_path, 'wb') as f:
                f.write(zip_data)
            
            # Extract zip with proper file handle management
            with zipfile.ZipFile(temp_zip_path, 'r') as zipf:
                zipf.extractall(output_path)
            
            # Force garbage collection to release file handles
            import gc
            gc.collect()
            
            # Wait a moment for Windows to release file handles
            time.sleep(0.1)
            
            logging.info(f"Folder decrypted successfully to: {output_path}")
            
        except Exception as e:
            logging.error(f"Error decrypting folder: {e}")
            raise
        finally:
            # Clean up temp file with retry mechanism
            if temp_zip_path and os.path.exists(temp_zip_path):
                max_retries = 5
                for attempt in range(max_retries):
                    try:
                        os.unlink(temp_zip_path)
                        logging.info("Temporary file cleaned up successfully")
                        break
                    except PermissionError as e:
                        if attempt < max_retries - 1:
                            logging.warning(f"Attempt {attempt + 1}: Could not delete temp file, retrying in 0.5 seconds...")
                            time.sleep(0.5)
                        else:
                            logging.warning(f"Could not delete temporary file after {max_retries} attempts: {temp_zip_path}")
                            # File will be cleaned up by system temp cleanup eventually
                    except Exception as e:
                        logging.warning(f"Unexpected error cleaning up temp file: {e}")
                        break

class SecureFolderGUI:
    def __init__(self):
        # Set appearance mode and color theme
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        
        self.root = ctk.CTk()
        self.root.title("Advanced Folder Security System")
        self.root.geometry("800x600")
        self.root.resizable(True, True)
        
        self.manager = SecureFolderManager()
        self.timer_threads = {}
        
        self.setup_ui()
        
    def setup_ui(self):
        """Setup the user interface"""
        # Main title
        title_label = ctk.CTkLabel(
            self.root,
            text="🔒 Advanced Folder Security System",
            font=ctk.CTkFont(size=24, weight="bold")
        )
        title_label.pack(pady=20)
        
        # Subtitle
        subtitle_label = ctk.CTkLabel(
            self.root,
            text="Military-grade encryption with auto-destruct capabilities",
            font=ctk.CTkFont(size=14)
        )
        subtitle_label.pack(pady=(0, 20))
        
        # Main frame
        main_frame = ctk.CTkFrame(self.root)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Folder selection frame
        folder_frame = ctk.CTkFrame(main_frame)
        folder_frame.pack(fill="x", padx=20, pady=20)
        
        ctk.CTkLabel(
            folder_frame,
            text="📁 Select Folder to Secure:",
            font=ctk.CTkFont(size=16, weight="bold")
        ).pack(pady=10)
        
        self.folder_path_var = tk.StringVar()
        folder_entry = ctk.CTkEntry(
            folder_frame,
            textvariable=self.folder_path_var,
            placeholder_text="Choose folder path...",
            width=500,
            height=35
        )
        folder_entry.pack(side="left", padx=(10, 5), pady=10)
        
        browse_btn = ctk.CTkButton(
            folder_frame,
            text="Browse",
            command=self.browse_folder,
            width=100,
            height=35
        )
        browse_btn.pack(side="right", padx=(5, 10), pady=10)
        
        # Security settings frame
        security_frame = ctk.CTkFrame(main_frame)
        security_frame.pack(fill="x", padx=20, pady=20)
        
        ctk.CTkLabel(
            security_frame,
            text="🔐 Security Settings:",
            font=ctk.CTkFont(size=16, weight="bold")
        ).pack(pady=10)
        
        # Password frame
        password_frame = ctk.CTkFrame(security_frame)
        password_frame.pack(fill="x", padx=10, pady=10)
        
        ctk.CTkLabel(password_frame, text="Password:").pack(side="left", padx=10)
        self.password_var = tk.StringVar()
        password_entry = ctk.CTkEntry(
            password_frame,
            textvariable=self.password_var,
            show="*",
            placeholder_text="Enter strong password...",
            width=300
        )
        password_entry.pack(side="left", padx=10)
        
        # Show password checkbox
        self.show_password_var = tk.BooleanVar()
        show_pass_cb = ctk.CTkCheckBox(
            password_frame,
            text="Show",
            variable=self.show_password_var,
            command=self.toggle_password_visibility
        )
        show_pass_cb.pack(side="left", padx=10)
        
        # Timer settings frame
        timer_frame = ctk.CTkFrame(security_frame)
        timer_frame.pack(fill="x", padx=10, pady=10)
        
        self.auto_destruct_var = tk.BooleanVar()
        auto_destruct_cb = ctk.CTkCheckBox(
            timer_frame,
            text="Enable Auto-Destruct Timer",
            variable=self.auto_destruct_var,
            command=self.toggle_timer_settings
        )
        auto_destruct_cb.pack(side="left", padx=10)
        
        # Timer input frame
        self.timer_input_frame = ctk.CTkFrame(timer_frame)
        
        ctk.CTkLabel(self.timer_input_frame, text="Hours:").pack(side="left", padx=5)
        self.hours_var = tk.StringVar(value="0")
        hours_entry = ctk.CTkEntry(self.timer_input_frame, textvariable=self.hours_var, width=60)
        hours_entry.pack(side="left", padx=5)
        
        ctk.CTkLabel(self.timer_input_frame, text="Minutes:").pack(side="left", padx=5)
        self.minutes_var = tk.StringVar(value="30")
        minutes_entry = ctk.CTkEntry(self.timer_input_frame, textvariable=self.minutes_var, width=60)
        minutes_entry.pack(side="left", padx=5)
        
        # Action buttons frame
        action_frame = ctk.CTkFrame(main_frame)
        action_frame.pack(fill="x", padx=20, pady=20)
        
        encrypt_btn = ctk.CTkButton(
            action_frame,
            text="🔒 Encrypt & Secure Folder",
            command=self.encrypt_folder,
            font=ctk.CTkFont(size=14, weight="bold"),
            height=40,
            fg_color="green",
            hover_color="darkgreen"
        )
        encrypt_btn.pack(side="left", padx=10, pady=10, fill="x", expand=True)
        
        decrypt_btn = ctk.CTkButton(
            action_frame,
            text="🔓 Decrypt & Access Folder",
            command=self.decrypt_folder,
            font=ctk.CTkFont(size=14, weight="bold"),
            height=40,
            fg_color="orange",
            hover_color="darkorange"
        )
        decrypt_btn.pack(side="right", padx=10, pady=10, fill="x", expand=True)
        
        # Status frame
        status_frame = ctk.CTkFrame(main_frame)
        status_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        ctk.CTkLabel(
            status_frame,
            text="📊 Secured Folders Status:",
            font=ctk.CTkFont(size=16, weight="bold")
        ).pack(pady=10)
        
        # Status text widget
        self.status_text = ctk.CTkTextbox(
            status_frame,
            font=ctk.CTkFont(family="Courier", size=12)
        )
        self.status_text.pack(fill="both", expand=True, padx=10, pady=10)
        
        self.update_status_display()
        
        # Set password entry reference for show/hide functionality
        self.password_entry = password_entry
        
    def toggle_password_visibility(self):
        """Toggle password visibility"""
        if self.show_password_var.get():
            self.password_entry.configure(show="")
        else:
            self.password_entry.configure(show="*")
    
    def toggle_timer_settings(self):
        """Toggle timer settings visibility"""
        if self.auto_destruct_var.get():
            self.timer_input_frame.pack(side="right", padx=10)
        else:
            self.timer_input_frame.pack_forget()
    
    def browse_folder(self):
        """Browse and select folder"""
        folder_path = filedialog.askdirectory(
            title="Select folder to secure"
        )
        if folder_path:
            self.folder_path_var.set(folder_path)
    
    def validate_inputs(self):
        """Validate user inputs"""
        if not self.folder_path_var.get():
            messagebox.showerror("Error", "Please select a folder")
            return False
        
        if not self.password_var.get():
            messagebox.showerror("Error", "Please enter a password")
            return False
        
        if len(self.password_var.get()) < 8:
            messagebox.showerror("Error", "Password must be at least 8 characters long")
            return False
        
        return True
    
    def encrypt_folder(self):
        """Encrypt selected folder"""
        if not self.validate_inputs():
            return
        
        folder_path = self.folder_path_var.get()
        password = self.password_var.get()
        
        if not os.path.exists(folder_path):
            messagebox.showerror("Error", "Selected folder does not exist")
            return
        
        def encrypt_thread():
            try:
                self.update_status("🔄 Encrypting folder... Please wait...")
                
                encrypted_file = self.manager.encrypt_folder(folder_path, password)
                
                # Setup auto-destruct timer if enabled
                if self.auto_destruct_var.get():
                    hours = int(self.hours_var.get() or "0")
                    minutes = int(self.minutes_var.get() or "0")
                    
                    if hours > 0 or minutes > 0:
                        self.setup_auto_destruct_timer(encrypted_file, hours, minutes)
                
                # Save to config
                folder_name = os.path.basename(folder_path)
                self.manager.secured_folders[folder_name] = {
                    'encrypted_file': encrypted_file,
                    'created': datetime.now().isoformat(),
                    'auto_destruct': self.auto_destruct_var.get(),
                    'timer_hours': int(self.hours_var.get() or "0"),
                    'timer_minutes': int(self.minutes_var.get() or "0")
                }
                self.manager.save_config()
                
                self.root.after(0, lambda: [
                    messagebox.showinfo("Success", f"Folder encrypted successfully!\nEncrypted file: {encrypted_file}"),
                    self.update_status_display()
                ])
                
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Error", f"Encryption failed: {str(e)}"))
        
        threading.Thread(target=encrypt_thread, daemon=True).start()
    
    def decrypt_folder(self):
        """Decrypt folder"""
        encrypted_file = filedialog.askopenfilename(
            title="Select encrypted folder file",
            filetypes=[("Secure files", "*.secure"), ("All files", "*.*")]
        )
        
        if not encrypted_file:
            return
        
        password = self.password_var.get()
        if not password:
            messagebox.showerror("Error", "Please enter the password")
            return
        
        output_folder = filedialog.askdirectory(
            title="Select location to decrypt folder"
        )
        
        if not output_folder:
            return
        
        def decrypt_thread():
            try:
                self.update_status("🔄 Decrypting folder... Please wait...")
                
                self.manager.decrypt_folder(encrypted_file, password, output_folder)
                
                # Remove from timer if exists
                for folder_name, info in list(self.manager.secured_folders.items()):
                    if info.get('encrypted_file') == encrypted_file:
                        if folder_name in self.timer_threads:
                            self.timer_threads[folder_name].cancel()
                            del self.timer_threads[folder_name]
                        del self.manager.secured_folders[folder_name]
                        self.manager.save_config()
                        break
                
                self.root.after(0, lambda: [
                    messagebox.showinfo("Success", f"Folder decrypted successfully to:\n{output_folder}"),
                    self.update_status_display()
                ])
                
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Error", f"Decryption failed: {str(e)}\nPlease check your password."))
        
        threading.Thread(target=decrypt_thread, daemon=True).start()
    
    def setup_auto_destruct_timer(self, encrypted_file: str, hours: int, minutes: int):
        """Setup auto-destruct timer"""
        total_seconds = (hours * 3600) + (minutes * 60)
        
        def auto_destruct():
            try:
                if os.path.exists(encrypted_file):
                    self.manager.gutmann_secure_delete(encrypted_file)
                    
                    # Remove from config
                    for folder_name, info in list(self.manager.secured_folders.items()):
                        if info.get('encrypted_file') == encrypted_file:
                            del self.manager.secured_folders[folder_name]
                            if folder_name in self.timer_threads:
                                del self.timer_threads[folder_name]
                            break
                    
                    self.manager.save_config()
                    
                    self.root.after(0, lambda: [
                        messagebox.showwarning("Auto-Destruct", f"Encrypted file has been securely deleted:\n{encrypted_file}"),
                        self.update_status_display()
                    ])
                    
            except Exception as e:
                logging.error(f"Auto-destruct error: {e}")
        
        folder_name = os.path.basename(encrypted_file)
        timer = threading.Timer(total_seconds, auto_destruct)
        timer.start()
        self.timer_threads[folder_name] = timer
        
        logging.info(f"Auto-destruct timer set for {hours}h {minutes}m")
    
    def update_status(self, message: str):
        """Update status display"""
        self.root.after(0, lambda: self.status_text.insert("end", f"{datetime.now().strftime('%H:%M:%S')} - {message}\n"))
    
    def update_status_display(self):
        """Update the status display with current secured folders"""
        self.status_text.delete("0.0", "end")
        
        if not self.manager.secured_folders:
            self.status_text.insert("end", "No secured folders found.\n")
            return
        
        for folder_name, info in self.manager.secured_folders.items():
            created = datetime.fromisoformat(info['created'])
            status_text = f"📁 {folder_name}\n"
            status_text += f"   Created: {created.strftime('%Y-%m-%d %H:%M:%S')}\n"
            status_text += f"   File: {info['encrypted_file']}\n"
            
            if info.get('auto_destruct', False):
                hours = info.get('timer_hours', 0)
                minutes = info.get('timer_minutes', 0)
                destruct_time = created + timedelta(hours=hours, minutes=minutes)
                status_text += f"   Auto-Destruct: {destruct_time.strftime('%Y-%m-%d %H:%M:%S')}\n"
            
            status_text += f"   Status: {'🟢 Active' if os.path.exists(info['encrypted_file']) else '🔴 Not Found'}\n"
            status_text += "-" * 50 + "\n"
            
            self.status_text.insert("end", status_text)
    
    def run(self):
        """Run the application"""
        self.root.mainloop()

def main():
    """Main function"""
    try:
        app = SecureFolderGUI()
        app.run()
    except Exception as e:
        logging.error(f"Application error: {e}")
        messagebox.showerror("Critical Error", f"Application failed to start: {e}")

if __name__ == "__main__":
    main()
