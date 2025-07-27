"""
SecureCore:Enhanced_Version  - Military-grade folder encryption with auto-destruct capabilities.

Author: LMLK-seal
License: MIT
Version: 2.0.0
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
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import hashes, padding, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305, AESGCM
from cryptography.hazmat.backends import default_backend
import shutil
import zipfile
import tempfile
import logging
import hmac
import struct
import platform
import psutil
import multiprocessing
import zlib

# CORRECTED: Import argon2 directly for a more robust implementation
try:
    import argon2
    ARGON2_AVAILABLE = True
except ImportError:
    ARGON2_AVAILABLE = False


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('securecore_enhanced.log'),
        logging.StreamHandler()
    ]
)

class EncryptionEngine:
    """Advanced encryption engine with multiple cipher support"""

    def __init__(self):
        self.backend = default_backend()
        self.argon2_available = ARGON2_AVAILABLE
        self.supported_ciphers = {
            'AES-256-GCM': self._aes_gcm_encrypt,
            'AES-256-CBC': self._aes_cbc_encrypt,
            'ChaCha20-Poly1305': self._chacha20_encrypt,
            'AES-256-CTR': self._aes_ctr_encrypt,
            'Hybrid-RSA-AES': self._hybrid_encrypt
        }
        self.decrypt_methods = {
            'AES-256-GCM': self._aes_gcm_decrypt,
            'AES-256-CBC': self._aes_cbc_decrypt,
            'ChaCha20-Poly1305': self._chacha20_decrypt,
            'AES-256-CTR': self._aes_ctr_decrypt,
            'Hybrid-RSA-AES': self._hybrid_decrypt
        }
        self.kdf_methods = {
            'PBKDF2-SHA256': self._pbkdf2_sha256,
            'PBKDF2-SHA512': self._pbkdf2_sha512,
            'Scrypt': self._scrypt_kdf,
            'Argon2': self._argon2_kdf
        }
        self.hw_acceleration = self._detect_hardware_acceleration()

    def _detect_hardware_acceleration(self):
        features = {
            'aes_ni': False,
            'avx2': False,
            'cpu_cores': multiprocessing.cpu_count(),
            'memory_gb': round(psutil.virtual_memory().total / (1024**3))
        }
        try:
            import cpuinfo
            cpu_info = cpuinfo.get_cpu_info()
            features['aes_ni'] = 'aes' in cpu_info.get('flags', [])
            features['avx2'] = 'avx2' in cpu_info.get('flags', [])
        except ImportError:
            features['aes_ni'] = 'Intel' in platform.processor() or 'AMD' in platform.processor()
        logging.info(f"Hardware acceleration detected: {features}")
        return features

    def _pbkdf2_sha256(self, password: str, salt: bytes, iterations: int = 100000) -> bytes:
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations, backend=self.backend)
        return kdf.derive(password.encode())

    def _pbkdf2_sha512(self, password: str, salt: bytes, iterations: int = 100000) -> bytes:
        kdf = PBKDF2HMAC(algorithm=hashes.SHA512(), length=32, salt=salt, iterations=iterations, backend=self.backend)
        return kdf.derive(password.encode())

    def _scrypt_kdf(self, password: str, salt: bytes, n: int = 2**14, r: int = 8, p: int = 1) -> bytes:
        kdf = Scrypt(salt=salt, length=32, n=n, r=r, p=p, backend=self.backend)
        return kdf.derive(password.encode())

    def _argon2_kdf(self, password: str, salt: bytes) -> bytes:
        """
        Derive key using argon2-cffi directly for maximum stability.
        Falls back to Scrypt if Argon2 is not available.
        """
        if self.argon2_available:
            try:
                # Use argon2.low_level.hash_secret_raw for direct key derivation.
                # This bypasses the cryptography wrapper entirely.
                return argon2.low_level.hash_secret_raw(
                    secret=password.encode(),
                    salt=salt,
                    time_cost=3,
                    memory_cost=65536,  # 64 MiB
                    parallelism=4,      # 4 lanes/threads
                    hash_len=32,
                    type=argon2.low_level.Type.ID  # Use Argon2id variant
                )
            except Exception as e:
                logging.error(f"Direct Argon2 call failed: {e}. Falling back to Scrypt.")
                return self._scrypt_kdf(password, salt)
        else:
            logging.warning("Argon2 not available, using Scrypt as fallback. To enable, run: pip install argon2-cffi")
            return self._scrypt_kdf(password, salt)

    def _aes_gcm_encrypt(self, data: bytes, key: bytes) -> bytes:
        nonce = secrets.token_bytes(12)
        cipher = AESGCM(key)
        return nonce + cipher.encrypt(nonce, data, None)

    def _aes_gcm_decrypt(self, encrypted_data: bytes, key: bytes) -> bytes:
        nonce = encrypted_data[:12]
        cipher = AESGCM(key)
        return cipher.decrypt(nonce, encrypted_data[12:], None)

    def _aes_cbc_encrypt(self, data: bytes, key: bytes) -> bytes:
        iv = secrets.token_bytes(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()
        return iv + encryptor.update(padded_data) + encryptor.finalize()

    def _aes_cbc_decrypt(self, encrypted_data: bytes, key: bytes) -> bytes:
        iv = encrypted_data[:16]
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(encrypted_data[16:]) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        return unpadder.update(padded_data) + unpadder.finalize()

    def _chacha20_encrypt(self, data: bytes, key: bytes) -> bytes:
        nonce = secrets.token_bytes(12)
        cipher = ChaCha20Poly1305(key)
        return nonce + cipher.encrypt(nonce, data, None)

    def _chacha20_decrypt(self, encrypted_data: bytes, key: bytes) -> bytes:
        nonce = encrypted_data[:12]
        cipher = ChaCha20Poly1305(key)
        return cipher.decrypt(nonce, encrypted_data[12:], None)

    def _aes_ctr_encrypt(self, data: bytes, key: bytes) -> bytes:
        nonce = secrets.token_bytes(16)
        cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=self.backend)
        encryptor = cipher.encryptor()
        return nonce + encryptor.update(data) + encryptor.finalize()

    def _aes_ctr_decrypt(self, encrypted_data: bytes, key: bytes) -> bytes:
        nonce = encrypted_data[:16]
        cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=self.backend)
        decryptor = cipher.decryptor()
        return decryptor.update(encrypted_data[16:]) + decryptor.finalize()

    def _generate_rsa_keypair(self) -> tuple:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=self.backend)
        return private_key, private_key.public_key()

    def _hybrid_encrypt(self, data: bytes, key: bytes) -> bytes:
        private_key, public_key = self._generate_rsa_keypair()
        aes_key = secrets.token_bytes(32)
        encrypted_data = self._aes_gcm_encrypt(data, aes_key)
        encrypted_aes_key = public_key.encrypt(aes_key, asym_padding.OAEP(mgf=asym_padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        private_key_bytes = private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.BestAvailableEncryption(key))
        return struct.pack('!I', len(private_key_bytes)) + private_key_bytes + struct.pack('!I', len(encrypted_aes_key)) + encrypted_aes_key + encrypted_data

    def _hybrid_decrypt(self, encrypted_data: bytes, key: bytes) -> bytes:
        offset = 0
        private_key_length = struct.unpack('!I', encrypted_data[offset:offset+4])[0]; offset += 4
        private_key_bytes = encrypted_data[offset:offset+private_key_length]; offset += private_key_length
        encrypted_aes_key_length = struct.unpack('!I', encrypted_data[offset:offset+4])[0]; offset += 4
        encrypted_aes_key = encrypted_data[offset:offset+encrypted_aes_key_length]; offset += encrypted_aes_key_length
        aes_encrypted_data = encrypted_data[offset:]
        private_key = serialization.load_pem_private_key(private_key_bytes, password=key, backend=self.backend)
        aes_key = private_key.decrypt(encrypted_aes_key, asym_padding.OAEP(mgf=asym_padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        return self._aes_gcm_decrypt(aes_encrypted_data, aes_key)

    def encrypt_with_integrity(self, data: bytes, password: str, cipher: str = 'AES-256-GCM', kdf_method: str = 'PBKDF2-SHA256', compression: bool = True) -> bytes:
        try:
            compressed_flag = b'\x01' if compression else b'\x00'
            if compression: data = zlib.compress(data, level=9)
            salt = secrets.token_bytes(32)
            key = self.kdf_methods.get(kdf_method, self._pbkdf2_sha256)(password, salt)
            encrypted_data = self.supported_ciphers.get(cipher, self._aes_gcm_encrypt)(data, key)
            header = b'SECURECORE_V2' + cipher.encode('utf-8').ljust(32, b'\x00') + kdf_method.encode('utf-8').ljust(32, b'\x00') + compressed_flag + salt
            hmac_key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt + b'HMAC', 50000)
            integrity_hash = hmac.new(hmac_key, header + encrypted_data, hashlib.sha256).digest()
            return header + integrity_hash + encrypted_data
        except Exception as e:
            logging.error(f"Enhanced encryption error: {e}")
            raise

    def decrypt_with_integrity(self, encrypted_data: bytes, password: str) -> bytes:
        try:
            if not encrypted_data.startswith(b'SECURECORE_V2'): raise ValueError("Invalid file format or corrupted data")
            header_len = 13 + 32 + 32 + 1 + 32
            header = encrypted_data[:header_len]
            integrity_hash = encrypted_data[header_len:header_len+32]
            ciphertext = encrypted_data[header_len+32:]
            
            cipher = header[13:45].rstrip(b'\x00').decode('utf-8')
            kdf_method = header[45:77].rstrip(b'\x00').decode('utf-8')
            compressed_flag = header[77:78]
            salt = header[78:110]

            hmac_key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt + b'HMAC', 50000)
            expected_hash = hmac.new(hmac_key, header + ciphertext, hashlib.sha256).digest()
            if not hmac.compare_digest(integrity_hash, expected_hash):
                raise ValueError("Integrity check failed - data may be corrupted or password incorrect")

            key = self.kdf_methods.get(kdf_method, self._pbkdf2_sha256)(password, salt)
            decrypted_data = self.decrypt_methods.get(cipher, self._aes_gcm_decrypt)(ciphertext, key)
            
            if compressed_flag == b'\x01': decrypted_data = zlib.decompress(decrypted_data)
            return decrypted_data
        except Exception as e:
            logging.error(f"Enhanced decryption error: {e}")
            raise

class SecureFolderManager:
    def __init__(self):
        self.encryption_engine = EncryptionEngine()
        self.config_file = "securecore_config.json"
        self.load_config()

    def load_config(self):
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f: self.secured_folders = json.load(f)
            else: self.secured_folders = {}
        except Exception as e:
            logging.error(f"Error loading config: {e}")
            self.secured_folders = {}

    def save_config(self):
        try:
            with open(self.config_file, 'w') as f: json.dump(self.secured_folders, f, indent=2)
        except Exception as e: logging.error(f"Error saving config: {e}")

    def gutmann_secure_delete(self, file_path: str):
        if not os.path.exists(file_path): return
        try:
            file_size = os.path.getsize(file_path)
            patterns = [lambda: secrets.token_bytes(1024) for _ in range(4)] + [lambda: p * 1024 for p in [b'\x55', b'\xAA']] + [lambda: p * 342 for p in [b'\x92\x49\x24', b'\x49\x24\x92', b'\x24\x92\x49']] + [lambda: bytes([i])*1024 for i in range(16)] + [lambda: p * 342 for p in [b'\x92\x49\x24', b'\x49\x24\x92', b'\x24\x92\x49', b'\x6D\xB6\xDB', b'\xB6\xDB\x6D', b'\xDB\x6D\xB6']] + [lambda: secrets.token_bytes(1024) for _ in range(5)]
            with open(file_path, 'r+b') as f:
                for pattern_func in patterns:
                    f.seek(0)
                    remaining = file_size
                    while remaining > 0:
                        pattern = pattern_func()
                        chunk_size = min(len(pattern), remaining)
                        f.write(pattern[:chunk_size])
                        remaining -= chunk_size
                    f.flush(); os.fsync(f.fileno())
            os.remove(file_path)
            logging.info(f"Gutmann secure deletion completed for: {file_path}")
        except Exception as e: logging.error(f"Error in Gutmann deletion: {e}")

    def secure_delete_folder(self, folder_path: str, progress_callback=None, total_files_in_folder=0, progress_start=0.0, progress_range=1.0):
        if not os.path.exists(folder_path): return
        try:
            files_to_delete = []
            for root, _, files in os.walk(folder_path):
                for file in files: files_to_delete.append(os.path.join(root, file))
            
            for i, file_path in enumerate(files_to_delete):
                if progress_callback and total_files_in_folder > 0:
                    progress = progress_start + ((i + 1) / total_files_in_folder) * progress_range
                    progress_callback(progress, f"Securely deleting: {os.path.basename(file_path)} ({i+1}/{total_files_in_folder})")
                self.gutmann_secure_delete(file_path)
            
            shutil.rmtree(folder_path, ignore_errors=True)
            logging.info(f"Secure folder deletion completed: {folder_path}")
        except Exception as e: logging.error(f"Error in secure folder deletion: {e}")

    def encrypt_folder_enhanced(self, folder_path: str, password: str, cipher: str, kdf_method: str, compression: bool, progress_callback=None) -> str:
        temp_zip_path = None
        try:
            total_files = sum(len(files) for _, _, files in os.walk(folder_path))
            if total_files == 0: total_files = 1

            temp_zip = tempfile.NamedTemporaryFile(suffix='.zip', delete=False)
            temp_zip_path = temp_zip.name
            temp_zip.close()
            
            with zipfile.ZipFile(temp_zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                files_zipped = 0
                for root, _, files in os.walk(folder_path):
                    for file in files:
                        file_path = os.path.join(root, file)
                        arcname = os.path.relpath(file_path, folder_path)
                        zipf.write(file_path, arcname)
                        files_zipped += 1
                        if progress_callback:
                            progress = (files_zipped / total_files) * 0.5
                            progress_callback(progress, f"Compressing: {file} ({files_zipped}/{total_files})")
            
            with open(temp_zip_path, 'rb') as f: zip_data = f.read()

            if progress_callback: progress_callback(0.55, "Encrypting data...")
            encrypted_data = self.encryption_engine.encrypt_with_integrity(zip_data, password, cipher, kdf_method, compression)
            
            encrypted_file_path = folder_path + '.securecore'
            with open(encrypted_file_path, 'wb') as f: f.write(encrypted_data)

            import gc; gc.collect(); time.sleep(0.1)

            self.secure_delete_folder(folder_path, progress_callback, total_files, 0.6, 0.4)
            if progress_callback: progress_callback(1.0, "Encryption complete!")

            return encrypted_file_path
        except Exception as e:
            logging.error(f"Error encrypting folder: {e}"); raise
        finally:
            if temp_zip_path and os.path.exists(temp_zip_path):
                try: os.unlink(temp_zip_path)
                except Exception as e: logging.warning(f"Could not delete temp file: {temp_zip_path}, error: {e}")

    def decrypt_folder_enhanced(self, encrypted_file_path: str, password: str, output_path: str, progress_callback=None):
        temp_zip_path = None
        try:
            if progress_callback: progress_callback(0.0, "Reading encrypted file...")
            with open(encrypted_file_path, 'rb') as f: encrypted_data = f.read()
            
            if progress_callback: progress_callback(0.1, "Decrypting and verifying integrity...")
            zip_data = self.encryption_engine.decrypt_with_integrity(encrypted_data, password)
            if progress_callback: progress_callback(0.5, "Decryption complete. Extracting files...")
            
            temp_zip = tempfile.NamedTemporaryFile(suffix='.zip', delete=False)
            temp_zip_path = temp_zip.name
            temp_zip.close()
            with open(temp_zip_path, 'wb') as f: f.write(zip_data)

            with zipfile.ZipFile(temp_zip_path, 'r') as zipf:
                infolist = zipf.infolist()
                total_files = len(infolist) if infolist else 1
                for i, item in enumerate(infolist):
                    zipf.extract(item, output_path)
                    if progress_callback:
                        progress = 0.5 + ((i + 1) / total_files) * 0.5
                        progress_callback(progress, f"Extracting: {item.filename} ({i+1}/{total_files})")
            
            import gc; gc.collect(); time.sleep(0.1)
            if progress_callback: progress_callback(1.0, "Decryption and extraction complete!")
            logging.info(f"Enhanced folder decryption completed: {output_path}")
        except Exception as e:
            logging.error(f"Error in enhanced decryption: {e}"); raise
        finally:
            if temp_zip_path and os.path.exists(temp_zip_path):
                try: os.unlink(temp_zip_path)
                except Exception as e: logging.warning(f"Could not delete temp file: {temp_zip_path}, error: {e}")

class SecureCoreGUI:
    def __init__(self):
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        self.root = ctk.CTk()
        self.root.title("SecureCore - Enhanced Encryption System")
        self.root.geometry("950x750")
        self.root.minsize(900, 700)
        self.manager = SecureFolderManager()
        self.timer_threads = {}
        self.setup_enhanced_ui()

    def setup_enhanced_ui(self):
        self.root.grid_columnconfigure(0, weight=1)
        self.root.grid_rowconfigure(3, weight=1)

        title_label = ctk.CTkLabel(self.root, text="🔐 SecureCore - Enhanced Encryption", font=ctk.CTkFont(size=26, weight="bold"))
        title_label.grid(row=0, column=0, padx=20, pady=(20, 5), sticky="n")
        subtitle_label = ctk.CTkLabel(self.root, text="Military-grade multi-cipher encryption with integrity verification", font=ctk.CTkFont(size=14))
        subtitle_label.grid(row=1, column=0, padx=20, pady=(0, 20), sticky="n")

        main_frame = ctk.CTkFrame(self.root)
        main_frame.grid(row=2, column=0, padx=20, pady=0, sticky="ew")
        main_frame.grid_columnconfigure(0, weight=1)

        folder_frame = ctk.CTkFrame(main_frame)
        folder_frame.grid(row=0, column=0, padx=20, pady=10, sticky="ew")
        folder_frame.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(folder_frame, text="📁 Select Folder to Secure:", font=ctk.CTkFont(size=16, weight="bold")).grid(row=0, column=0, columnspan=3, pady=(10,0))
        self.folder_path_var = tk.StringVar()
        ctk.CTkEntry(folder_frame, textvariable=self.folder_path_var, placeholder_text="Choose folder path...", height=35).grid(row=1, column=0, columnspan=2, padx=10, pady=10, sticky="ew")
        ctk.CTkButton(folder_frame, text="Browse", command=self.browse_folder, width=100, height=35).grid(row=1, column=2, padx=(0, 10), pady=10)

        settings_frame = ctk.CTkFrame(main_frame)
        settings_frame.grid(row=1, column=0, padx=20, pady=10, sticky="ew")
        settings_frame.grid_columnconfigure((0, 1), weight=1)
        ctk.CTkLabel(settings_frame, text="🛡️ Enhanced Security Settings:", font=ctk.CTkFont(size=16, weight="bold")).grid(row=0, column=0, columnspan=2, pady=(10,5))
        
        left_settings = ctk.CTkFrame(settings_frame)
        left_settings.grid(row=1, column=0, padx=10, pady=10, sticky="nsew")
        left_settings.grid_columnconfigure(1, weight=1)
        
        ctk.CTkLabel(left_settings, text="Password:").grid(row=0, column=0, padx=10, pady=5, sticky="w")
        self.password_var = tk.StringVar()
        self.password_entry = ctk.CTkEntry(left_settings, textvariable=self.password_var, show="*", placeholder_text="Enter strong password...")
        self.password_entry.grid(row=0, column=1, padx=(0, 10), pady=5, sticky="ew")
        self.show_password_var = tk.BooleanVar()
        ctk.CTkCheckBox(left_settings, text="Show", variable=self.show_password_var, command=self.toggle_password_visibility).grid(row=0, column=2, padx=(0,10))

        ctk.CTkLabel(left_settings, text="Encryption Algorithm:").grid(row=1, column=0, padx=10, pady=5, sticky="w")
        self.cipher_var = tk.StringVar(value="AES-256-GCM")
        ctk.CTkComboBox(left_settings, values=list(self.manager.encryption_engine.supported_ciphers.keys()), variable=self.cipher_var).grid(row=1, column=1, columnspan=2, padx=(0,10), pady=5, sticky="ew")

        ctk.CTkLabel(left_settings, text="Key Derivation:").grid(row=2, column=0, padx=10, pady=5, sticky="w")
        self.kdf_var = tk.StringVar(value="Argon2" if self.manager.encryption_engine.argon2_available else "Scrypt")
        ctk.CTkComboBox(left_settings, values=list(self.manager.encryption_engine.kdf_methods.keys()), variable=self.kdf_var).grid(row=2, column=1, columnspan=2, padx=(0,10), pady=5, sticky="ew")

        right_settings = ctk.CTkFrame(settings_frame)
        right_settings.grid(row=1, column=1, padx=10, pady=10, sticky="nsew")
        
        self.compression_var = tk.BooleanVar(value=True)
        ctk.CTkCheckBox(right_settings, text="Enable Compression (Reduces file size)", variable=self.compression_var).pack(anchor="w", padx=10, pady=5)
        
        self.auto_destruct_var = tk.BooleanVar()
        ctk.CTkCheckBox(right_settings, text="Enable Auto-Destruct Timer", variable=self.auto_destruct_var, command=self.toggle_timer_settings).pack(anchor="w", padx=10, pady=5)

        self.timer_input_frame = ctk.CTkFrame(right_settings)
        ctk.CTkLabel(self.timer_input_frame, text="Hours:").pack(side="left", padx=(10, 5))
        self.hours_var = tk.StringVar(value="0")
        ctk.CTkEntry(self.timer_input_frame, textvariable=self.hours_var, width=50).pack(side="left")
        ctk.CTkLabel(self.timer_input_frame, text="Mins:").pack(side="left", padx=5)
        self.minutes_var = tk.StringVar(value="30")
        ctk.CTkEntry(self.timer_input_frame, textvariable=self.minutes_var, width=50).pack(side="left", padx=(0, 10))

        hw_info = self.manager.encryption_engine.hw_acceleration
        hw_text = f"🖥️ Hardware: {hw_info['cpu_cores']} cores, {hw_info['memory_gb']}GB RAM" + (" ⚡ AES-NI" if hw_info['aes_ni'] else "") + (" ⚡ AVX2" if hw_info['avx2'] else "")
        ctk.CTkLabel(main_frame, text=hw_text, font=ctk.CTkFont(size=12)).grid(row=2, column=0, pady=5)

        action_frame = ctk.CTkFrame(main_frame)
        action_frame.grid(row=3, column=0, padx=20, pady=10, sticky="ew")
        action_frame.grid_columnconfigure((0, 1), weight=1)
        ctk.CTkButton(action_frame, text="🔒 Encrypt with Enhanced Security", command=self.encrypt_folder_enhanced, font=ctk.CTkFont(size=14, weight="bold"), height=40, fg_color="green", hover_color="darkgreen").grid(row=0, column=0, padx=10, pady=10, sticky="ew")
        ctk.CTkButton(action_frame, text="🔓 Decrypt & Verify Integrity", command=self.decrypt_folder_enhanced, font=ctk.CTkFont(size=14, weight="bold"), height=40, fg_color="orange", hover_color="darkorange").grid(row=0, column=1, padx=10, pady=10, sticky="ew")

        self.progress_frame = ctk.CTkFrame(main_frame)
        self.progress_frame.grid(row=4, column=0, padx=20, pady=5, sticky="ew")
        self.progress_frame.grid_columnconfigure(0, weight=1)
        self.progress_label = ctk.CTkLabel(self.progress_frame, text="Progress: Idle")
        self.progress_label.grid(row=0, column=0, padx=10, pady=(5,0), sticky="w")
        self.progress_bar = ctk.CTkProgressBar(self.progress_frame)
        self.progress_bar.set(0)
        self.progress_bar.grid(row=1, column=0, padx=10, pady=(0,5), sticky="ew")
        self.progress_frame.grid_remove()

        status_frame = ctk.CTkFrame(self.root)
        status_frame.grid(row=3, column=0, padx=20, pady=20, sticky="nsew")
        status_frame.grid_rowconfigure(1, weight=1)
        status_frame.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(status_frame, text="📊 Enhanced Security Status & Operations Log:", font=ctk.CTkFont(size=16, weight="bold")).grid(row=0, column=0, padx=10, pady=10, sticky="w")
        self.status_text = ctk.CTkTextbox(status_frame, font=ctk.CTkFont(family="Courier", size=11))
        self.status_text.grid(row=1, column=0, padx=10, pady=(0,10), sticky="nsew")

        self.display_encryption_info()

    def display_encryption_info(self):
        """Display encryption engine information and status."""
        info_text = "🔐 SecureCore Engine Initialized\n"
        info_text += "=" * 80 + "\n"
        info_text += f"✅ Supported Ciphers: {', '.join(self.manager.encryption_engine.supported_ciphers.keys())}\n"
        info_text += f"✅ Supported KDFs: {', '.join(self.manager.encryption_engine.kdf_methods.keys())}\n"
        
        if self.manager.encryption_engine.argon2_available:
            info_text += "✅ Argon2 Support: ENABLED (Highest Security, via direct argon2-cffi call)\n"
        else:
            info_text += "⚠️ Argon2 Support: DISABLED (using Scrypt as fallback). To enable, run: pip install argon2-cffi\n"
        
        info_text += "=" * 80 + "\n"
        self.status_text.insert("1.0", info_text)

    def toggle_password_visibility(self):
        self.password_entry.configure(show="" if self.show_password_var.get() else "*")

    def toggle_timer_settings(self):
        if self.auto_destruct_var.get(): self.timer_input_frame.pack(anchor="w", padx=10, pady=5)
        else: self.timer_input_frame.pack_forget()

    def browse_folder(self):
        if path := filedialog.askdirectory(title="Select folder to secure"): self.folder_path_var.set(path)
    
    def update_progress(self, value: float, text: str):
        self.progress_bar.set(value)
        self.progress_label.configure(text=text)

    def validate_enhanced_inputs(self, is_encrypt=True):
        if is_encrypt and not self.folder_path_var.get():
            messagebox.showerror("Error", "Please select a folder.")
            return False
        if not self.password_var.get():
            messagebox.showerror("Error", "Please enter a password.")
            return False
        if is_encrypt and len(self.password_var.get()) < 12:
            if not messagebox.askyesno("Weak Password", "Password is short. For best security, use at least 12 characters.\nContinue anyway?"):
                return False
        return True

    def encrypt_folder_enhanced(self):
        if not self.validate_enhanced_inputs(): return
        folder_path, password = self.folder_path_var.get(), self.password_var.get()
        cipher, kdf, compression = self.cipher_var.get(), self.kdf_var.get(), self.compression_var.get()
        if not os.path.exists(folder_path):
            messagebox.showerror("Error", "Selected folder does not exist."); return

        def encrypt_thread():
            self.root.after(0, self.progress_frame.grid)
            try:
                start_time = time.time()
                self.update_status(f"🔄 Starting enhanced encryption...\n  Algorithm: {cipher}, KDF: {kdf}, Compression: {'On' if compression else 'Off'}")
                
                encrypted_file = self.manager.encrypt_folder_enhanced(folder_path, password, cipher, kdf, compression, self.update_progress)
                duration = round(time.time() - start_time, 2)
                
                if self.auto_destruct_var.get():
                    if (hours := int(self.hours_var.get() or "0")) > 0 or (minutes := int(self.minutes_var.get() or "0")) > 0:
                        self.setup_auto_destruct_timer(encrypted_file, hours, minutes)

                folder_name = os.path.basename(folder_path)
                self.manager.secured_folders[folder_name] = {
                    'encrypted_file': encrypted_file, 'created': datetime.now().isoformat(), 'cipher': cipher, 'kdf_method': kdf, 'compression': compression,
                    'auto_destruct': self.auto_destruct_var.get(), 'timer_hours': int(self.hours_var.get() or "0"), 'timer_minutes': int(self.minutes_var.get() or "0"), 'encryption_time': duration
                }
                self.manager.save_config()
                
                self.root.after(0, lambda: [
                    self.update_status(f"✅ Enhanced encryption completed in {duration}s. File: {encrypted_file}"),
                    messagebox.showinfo("Success", f"Folder encrypted successfully!\n\nFile: {encrypted_file}")
                ])
            except Exception as e:
                self.root.after(0, lambda err=e: [
                    self.update_status(f"❌ Encryption failed: {err}"),
                    messagebox.showerror("Encryption Error", f"Encryption failed: {err}")
                ])
            finally:
                self.root.after(1000, self.progress_frame.grid_remove)

        threading.Thread(target=encrypt_thread, daemon=True).start()

    def decrypt_folder_enhanced(self):
        if not (encrypted_file := filedialog.askopenfilename(title="Select encrypted file", filetypes=[("SecureCore files", "*.securecore"), ("All files", "*.*")])): return
        if not self.validate_enhanced_inputs(is_encrypt=False): return
        if not (output_folder := filedialog.askdirectory(title="Select location to decrypt folder")): return

        password = self.password_var.get()

        def decrypt_thread():
            self.root.after(0, self.progress_frame.grid)
            try:
                start_time = time.time()
                self.update_status("🔄 Starting enhanced decryption...")
                self.manager.decrypt_folder_enhanced(encrypted_file, password, output_folder, self.update_progress)
                duration = round(time.time() - start_time, 2)
                
                for folder_name, info in list(self.manager.secured_folders.items()):
                    if info.get('encrypted_file') == encrypted_file:
                        if folder_name in self.timer_threads:
                            self.timer_threads[folder_name].cancel()
                            del self.timer_threads[folder_name]
                        del self.manager.secured_folders[folder_name]
                        self.manager.save_config(); break
                
                self.root.after(0, lambda: [
                    self.update_status(f"✅ Decryption completed in {duration}s. Decrypted to: {output_folder}"),
                    messagebox.showinfo("Success", f"Folder decrypted successfully!\n\nLocation: {output_folder}")
                ])
            except Exception as e:
                error_msg = f"Decryption failed: {e}"
                messagebox_title = "Decryption Error"
                if "Integrity check failed" in str(e):
                    error_msg = "INTEGRITY CHECK FAILED. Data may be corrupted or password incorrect."
                    messagebox_title = "Integrity Error"
                
                self.root.after(0, lambda err=error_msg, title=messagebox_title: [
                    self.update_status(f"❌ {err}"),
                    messagebox.showerror(title, err)
                ])
            finally:
                self.root.after(1000, self.progress_frame.grid_remove)

        threading.Thread(target=decrypt_thread, daemon=True).start()
    
    def setup_auto_destruct_timer(self, encrypted_file: str, hours: int, minutes: int):
        def auto_destruct():
            try:
                if os.path.exists(encrypted_file):
                    self.manager.gutmann_secure_delete(encrypted_file)
                    for folder_name, info in list(self.manager.secured_folders.items()):
                        if info.get('encrypted_file') == encrypted_file:
                            del self.manager.secured_folders[folder_name]
                            if folder_name in self.timer_threads: del self.timer_threads[folder_name]
                            break
                    self.manager.save_config()
                    self.root.after(0, lambda: [
                        self.update_status(f"💥 Auto-destruct executed: {encrypted_file}"),
                        messagebox.showwarning("Auto-Destruct", f"Encrypted file has been securely deleted:\n{encrypted_file}")
                    ])
            except Exception as e: logging.error(f"Auto-destruct error: {e}")
        
        total_seconds = (hours * 3600) + (minutes * 60)
        folder_name = os.path.basename(encrypted_file)
        timer = threading.Timer(total_seconds, auto_destruct)
        timer.daemon = True
        timer.start()
        self.timer_threads[folder_name] = timer
        self.update_status(f"⏰ Auto-destruct timer set for {hours}h {minutes}m for {os.path.basename(encrypted_file)}")

    def update_status(self, message: str):
        timestamp = datetime.now().strftime('%H:%M:%S')
        self.root.after(0, lambda: self.status_text.insert("end", f"{timestamp} - {message}\n"))
        self.root.after(0, lambda: self.status_text.see("end"))
    
    def run(self):
        self.root.mainloop()

def main():
    try:
        app = SecureCoreGUI()
        app.run()
    except Exception as e:
        logging.critical(f"Application failed to start: {e}", exc_info=True)
        messagebox.showerror("Critical Error", f"SecureCore failed to start: {e}")

if __name__ == "__main__":
    main()
