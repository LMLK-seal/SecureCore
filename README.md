# 🔐 SecureCore

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://python.org)
[![Platform](https://img.shields.io/badge/platform-Windows-lightgrey.svg)](https://microsoft.com/windows)
[![Security](https://img.shields.io/badge/encryption-AES--256-green.svg)](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)
[![GUI](https://img.shields.io/badge/GUI-CustomTkinter-orange.svg)](https://github.com/TomSchimansky/CustomTkinter)

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

---

## 📸 Screenshots

### Main Interface
![SecureCore Main Interface](https://github.com/LMLK-seal/SecureCore/blob/main/Preview.jpg?raw=true)

---

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
   pip install -r requirements.txt
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
