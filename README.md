# 🔐 SecureCore

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://python.org)
[![Platform](https://img.shields.io/badge/platform-Windows-lightgrey.svg)](https://microsoft.com/windows)
[![Security](https://img.shields.io/badge/encryption-AES--256-green.svg)](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)
[![GUI](https://img.shields.io/badge/GUI-CustomTkinter-orange.svg)](https://github.com/TomSchimansky/CustomTkinter)

![SecureCoreLogo](https://github.com/LMLK-seal/SecureCore/blob/main/SecureCoreLogo.png?raw=true)

> **Military-grade folder encryption with auto-destruct capabilities**

SecureCore is a professional-grade folder security application that provides military-standard AES-256 encryption combined with Gutmann secure deletion methods. Designed for users who require the highest level of data protection with user-friendly operation.

---

## 🌟 Key Features

### 🛡️ **Military-Grade Security**
- **AES-256-CBC Encryption** with PBKDF2 key derivation
- **100,000 iterations** for password hashing resistance
- **Cryptographically secure** random salt and IV generation
- **PKCS7 padding** for complete block cipher compatibility

### 🔥 **Gutmann Secure Deletion**
- **35-pass overwrite** pattern for complete data destruction
- **Multiple bit patterns** prevent forensic data recovery
- **File system synchronization** after each deletion pass
- **DoD 5220.22-M compliant** secure deletion standards

### ⏱️ **Auto-Destruct Timer**
- **Configurable countdown** timer (hours/minutes)
- **Background monitoring** with automatic secure deletion
- **Persistent configuration** survives application restarts
- **Emergency destruction** for sensitive time-critical data

### 🎨 **Professional Interface**
- **Modern dark theme** with CustomTkinter framework
- **Intuitive folder browsing** and selection
- **Real-time status monitoring** and logging
- **Password visibility controls** for secure entry

## 🔐 SecureCore - Advanced version System (Simple Version)
<details>
<summary>Advanced version System (Simple Version)</summary>
## 🚀 Quick Start

### Prerequisites
```bash
Python 3.8+
Windows Operating System
```

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/LMLK-seal/securecore.git
   cd securecore
   ```

2. **Install dependencies:**
   ```bash
   pip install customtkinter cryptography
   ```

3. **Run SecureCore:**
   ```bash
   python securecore.py
   ```

### Dependencies
```
customtkinter>=5.2.0
cryptography>=41.0.0
```

---

## 📖 Usage Guide

### 🔒 **Encrypting a Folder**

1. **Launch SecureCore** and click "Browse" to select your target folder
2. **Enter a strong password** (minimum 8 characters recommended)
3. **Optional:** Enable auto-destruct timer with custom duration
4. **Click "Encrypt & Secure Folder"** - original folder will be securely deleted
5. **Encrypted file** saved as `[FolderName].secure`

### 🔓 **Decrypting a Folder**

1. **Click "Decrypt & Access Folder"**
2. **Select the `.secure` file** you want to decrypt  
3. **Enter the correct password** used during encryption
4. **Choose destination folder** for decrypted contents
5. **Access your restored files** in the selected location

### ⏱️ **Auto-Destruct Timer**

- **Enable the checkbox** in Security Settings
- **Set duration** in hours and minutes
- **Timer starts** immediately after successful encryption
- **Automatic deletion** occurs using Gutmann method when timer expires
- **Status monitoring** shows remaining time and active timers

---

## 🔧 Technical Specifications

### **Encryption Details**
| Component | Specification |
|-----------|---------------|
| **Algorithm** | AES-256-CBC |
| **Key Derivation** | PBKDF2-HMAC-SHA256 |
| **Iterations** | 100,000 |
| **Salt Length** | 128-bit (16 bytes) |
| **IV Length** | 128-bit (16 bytes) |
| **Padding** | PKCS7 |

### **Secure Deletion**
| Method | Details |
|--------|---------|
| **Standard** | Gutmann 35-pass method |
| **Patterns** | Random + Specific bit patterns |
| **Compliance** | DoD 5220.22-M compatible |
| **File Sync** | Force write to disk after each pass |

### **Security Features**
- ✅ **No plaintext password storage**
- ✅ **Cryptographically secure random generation**
- ✅ **Memory-safe operations**
- ✅ **Comprehensive audit logging**
- ✅ **Thread-safe timer operations**

---

## 📊 System Requirements

### **Minimum Requirements**
- **OS:** Windows 10/11 (64-bit)
- **Python:** 3.8 or higher
- **RAM:** 512 MB available memory
- **Storage:** 50 MB free disk space
- **Dependencies:** CustomTkinter, Cryptography

### **Recommended Requirements**
- **OS:** Windows 11 (64-bit)
- **Python:** 3.10+ 
- **RAM:** 2 GB available memory
- **Storage:** 1 GB free disk space (for temporary operations)
- **Processor:** Multi-core CPU for faster encryption
</details>

## 🔐 SecureCore - Enhanced version System
<details>
<summary>Enhanced version System</summary>

## 🛡️ Security Profiles & Cipher Recommendations

Choose the right security profile for your needs:

### 🥇 Tier 1: The Modern Gold Standard
**Profile Name:** Balanced & Recommended  
**Configuration:** AES-256-GCM + Scrypt

🔹 **Strength:** The ideal choice for most users. AES-GCM is the industry standard for high-performance, authenticated encryption. It's not only fast (often accelerated by your CPU's hardware) but also includes built-in integrity and authenticity checks, meaning it protects against both eavesdropping and tampering. Scrypt is a memory-hard KDF, which makes it extremely resistant to brute-force password guessing attacks using specialized hardware like GPUs or ASICs.

🔹 **Security Power:** Excellent. This combination protects your data with a top-tier modern cipher and shields your password with a KDF designed to defeat well-funded attackers. It's the go-to choice for strong, everyday security.

🔹 **Best For:** Virtually all users and general-purpose file and folder encryption.

---

### 🏰 Tier 2: The Fortress
**Profile Name:** Maximum Paranoid / Future-Proof  
**Configuration:** AES-256-GCM + Argon2

🔹 **Strength:** This pairing offers the highest level of security available in the application. While AES-GCM remains the cipher of choice, Argon2 is the current state-of-the-art KDF and the winner of the international Password Hashing Competition. It was specifically designed to be resilient against an even wider array of attacks than Scrypt, including trade-off attacks where an attacker uses more memory to reduce computation time.

🔹 **Security Power:** Exceptional. This is the strongest defense you can mount to protect your password. If you are protecting extremely sensitive data or are concerned about advances in computing power over the next decade, this is the combination to use.

⚠️ **Note:** Requires the `argon2-cffi` library to be installed.

🔹 **Best For:** Protecting nation-state level secrets, cryptographic keys, financial data, or for users who simply want the most robust security possible.

---

### ⚡ Tier 3: The Sprinter
**Profile Name:** High-Speed & Efficient  
**Configuration:** ChaCha20-Poly1305 + PBKDF2-SHA512

🔹 **Strength:** This profile prioritizes performance. ChaCha20-Poly1305 is a modern, authenticated cipher that is extremely fast, especially on platforms without dedicated AES hardware acceleration. It is a leading alternative to AES-GCM and is used by major tech companies like Google. PBKDF2-SHA512 is a very strong, time-tested KDF that is computationally expensive but not memory-hard, making it much faster to compute than Scrypt or Argon2.

🔹 **Security Power:** Very Strong & Fast. While PBKDF2 is theoretically more vulnerable to specialized hardware attacks than Scrypt/Argon2, it remains a formidable barrier. The encryption itself is top-tier. You are trading a fraction of theoretical KDF resilience for a significant gain in operational speed.

🔹 **Best For:** Encrypting very large files (like multi-gigabyte video archives), running on older computers, or any situation where performance is the primary concern.

---

### 🔄 Tier 4: The Modern Alternative
**Profile Name:** The Non-AES Path  
**Configuration:** ChaCha20-Poly1305 + Scrypt

🔹 **Strength:** This combination provides a security level equivalent to the "Modern Gold Standard" but uses a different family of cryptographic primitives. ChaCha20-Poly1305 offers excellent security and performance, and Scrypt provides the same memory-hard password protection. This is a great choice for cryptographic diversity.

🔹 **Security Power:** Excellent. It is just as secure as the AES-GCM + Scrypt combination. Choosing between them is a matter of preference for the underlying mathematics, not a difference in practical security.

🔹 **Best For:** Security-conscious users who prefer a robust and modern alternative to AES for any reason.

---

### 📜 Tier 5: The Classic (Legacy)
**Profile Name:** Legacy & Compatibility  
**Configuration:** AES-256-CBC + PBKDF2-SHA256

🔹 **Strength:** This pairing represents a "classic" security stack from several years ago. AES-CBC is an older encryption mode that, while secure when implemented correctly (as it is here), is more difficult to use safely than modern modes like GCM. PBKDF2-SHA256 is the most widely adopted KDF standard. Our application ensures this combination is secure by adding a separate integrity check (HMAC) on top.

🔹 **Security Power:** Robust and Widely Compatible. While not the absolute strongest combination offered, it is still very secure and represents a baseline that many older cryptographic tools can understand. The main reason to use this is for interoperability.

🔹 **Best For:** Situations where you might need to decrypt the file on an older system or with a different tool that may not support the latest ciphersuites like GCM or Scrypt.

## 🚀 Installation

### Prerequisites
- Python 3.8 or higher
- pip package manager

### Install Dependencies
```bash
pip install -r requirements.txt
```

### Requirements
```
customtkinter>=5.2.0
cryptography>=41.0.0
psutil>=5.9.0
py-cpuinfo>=9.0.0
argon2-cffi>=23.1.0
```

## 🎯 Features

### 🔒 Advanced Encryption
- **Multiple Cipher Support:** AES-256-GCM, AES-256-CBC, ChaCha20-Poly1305, AES-256-CTR, Hybrid-RSA-AES
- **Robust Key Derivation:** PBKDF2-SHA256/SHA512, Scrypt, Argon2
- **Integrity Verification:** Built-in HMAC authentication to detect tampering
- **Compression:** Optional data compression to reduce file sizes

### 🛡️ Security Features  
- **Gutmann Secure Deletion:** 35-pass overwrite for complete data destruction
- **Auto-Destruct Timer:** Automatic secure deletion after specified time
- **Hardware Acceleration:** Automatic detection and use of AES-NI and AVX2 instructions
- **Memory-Hard KDFs:** Protection against specialized hardware attacks

### 🖥️ User Interface
- **Modern GUI:** Dark-themed interface built with CustomTkinter
- **Real-time Progress:** Live encryption/decryption progress tracking
- **Hardware Detection:** Display of system capabilities and acceleration features
- **Operation Logging:** Comprehensive status and operation history

## 📖 Usage

1. **Launch the application:**
   ```bash
   python SecureCore.py
   ```

2. **Select a folder** to encrypt using the Browse button

3. **Choose your security profile:**
   - Select encryption algorithm
   - Choose key derivation function
   - Set optional features (compression, auto-destruct)

4. **Enter a strong password** (minimum 12 characters recommended)

5. **Click "Encrypt with Enhanced Security"** to secure your folder

6. **To decrypt:** Click "Decrypt & Verify Integrity" and select your .securecore file

## ⚠️ Security Recommendations

### 🔐 Password Guidelines
- Use at least 12 characters (longer is better)
- Include uppercase, lowercase, numbers, and symbols
- Avoid dictionary words and personal information
- Consider using a password manager

### 🛡️ Best Practices
- Always verify integrity after decryption
- Store encrypted files in secure locations
- Keep backups of important encrypted data
- Use the highest security tier for sensitive data
- Regularly update the application and dependencies

## 🔧 Technical Details

### Supported Algorithms
- **AES-256-GCM:** Authenticated encryption with built-in integrity
- **AES-256-CBC:** Classic block cipher with PKCS7 padding
- **ChaCha20-Poly1305:** Modern stream cipher with authentication
- **AES-256-CTR:** Counter mode for parallel processing
- **Hybrid-RSA-AES:** RSA key exchange with AES encryption

### Key Derivation Functions
- **PBKDF2-SHA256/SHA512:** Industry standard with configurable iterations
- **Scrypt:** Memory-hard function resistant to hardware attacks
- **Argon2:** State-of-the-art winner of Password Hashing Competition


</details>

## 📸 Screenshots

<details>
<summary>🖼️ SecureCore Advanced version </summary>

### Simple Main Interface
![Simple Main Interface](https://github.com/LMLK-seal/SecureCore/blob/main/Preview.jpg?raw=true)

</details>

<details>
<summary>🖼️ SecureCore Enhanced version</summary>

### Enhanced Main Interface
![Enhanced Main Interface](https://github.com/LMLK-seal/SecureCore/blob/main/Advanced_version_example.png?raw=true)

</details>

---

## ⚠️ Security Warnings

### **🚨 Critical Security Notes**

> **⚠️ DATA LOSS WARNING**  
> The Gutmann secure deletion process is **irreversible**. Always maintain secure backups of critical data before encryption.

> **🔐 PASSWORD SECURITY**  
> Use strong passwords with minimum 12 characters including uppercase, lowercase, numbers, and symbols. Lost passwords cannot be recovered.

> **⏰ AUTO-DESTRUCT CAUTION**  
> Auto-destruct timers will permanently delete encrypted data. Ensure you have sufficient time for legitimate access.

### **Best Practices**
- 🔹 **Test on non-critical data** first
- 🔹 **Use unique, complex passwords** for each encryption
- 🔹 **Run on trusted systems** only
- 🔹 **Monitor security logs** regularly
- 🔹 **Keep software updated** for latest security patches

---

## 📝 Logging & Monitoring

SecureCore maintains comprehensive logs for security auditing:

```
2024-07-24 22:15:30 - INFO - Folder encryption initiated: C:\Documents\SecretFolder
2024-07-24 22:15:45 - INFO - AES-256 encryption completed successfully
2024-07-24 22:15:46 - INFO - Gutmann secure deletion started
2024-07-24 22:16:12 - INFO - Auto-destruct timer set for 2h 30m
2024-07-24 22:16:12 - INFO - Folder secured: SecretFolder.secure
```

**Log Location:** `folder_security.log` in application directory

---

## 🤝 Contributing

We welcome contributions to SecureCore! Please follow these guidelines:

### **Contribution Guidelines**
- 🔹 Follow PEP 8 style guidelines
- 🔹 Add unit tests for new features
- 🔹 Update documentation for changes
- 🔹 Ensure security best practices
- 🔹 Test on Windows environment

### **Reporting Issues**
- Use GitHub Issues for bug reports
- Include system information and error logs
- Provide steps to reproduce issues
- Check existing issues before creating new ones

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

```
MIT License - Copyright (c) 2024 SecureCore Project
Permission is hereby granted, free of charge, to any person obtaining a copy...
```

---

## 🙏 Acknowledgments

- **Cryptography Library** - Robust encryption implementation
- **CustomTkinter** - Modern GUI framework
- **Peter Gutmann** - Secure deletion methodology research
- **NIST** - AES encryption standards
- **Security Community** - Best practices and recommendations

---

## 📞 Support & Contact

### **Getting Help**
- 📖 **Documentation:** [Wiki](https://github.com/LMLK-seal/securecore/wiki)
- 🐛 **Bug Reports:** [Issues](https://github.com/LMLK-seal/securecore/issues)
- 💬 **Discussions:** [GitHub Discussions](https://github.com/LMLK-seal/securecore/discussions)


**Do not report security issues publicly.**

---

## 🔖 Version History

### **v1.0.0** - Initial Release
- ✅ AES-256-CBC encryption implementation
- ✅ Gutmann 35-pass secure deletion
- ✅ Auto-destruct timer functionality
- ✅ Modern GUI with CustomTkinter
- ✅ Comprehensive logging system
- ✅ Windows file handling improvements

---

<div align="center">

**⭐ Star this repository if SecureCore helps protect your sensitive data! ⭐**

[![GitHub stars](https://img.shields.io/github/stars/yLMLK-seal/securecore?style=social)](https://github.com/LMLK-seal/securecore/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/LMLK-seal/securecore?style=social)](https://github.com/LMLK-seal/securecore/network)

---

**🔐 SecureCore - Your Data, Truly Secure 🔐**

</div>
