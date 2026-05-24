# 🛡️ CyberVault Security Platform v2.0

<div align="center">

![CyberVault Logo](https://img.shields.io/badge/CyberVault-v2.0-00d4ff?style=for-the-badge&logo=shield&logoColor=white)
![Security](https://img.shields.io/badge/Security-Operations-00ff88?style=for-the-badge&logo=security&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Multiplatform-ff6b00?style=for-the-badge&logo=windows&logoColor=white)

**Industrial-Grade Cybersecurity Operations Terminal with Advanced File Management**

[🚀 Live Demo](https://cybervault.onrender.com) | [📖 Local Setup](LOCAL_DEVELOPMENT.md) | [🐛 Issues](https://github.com/arapbett/cybervault/issues)

</div>

---

## 🌟 **Features**

### 🔒 **Advanced Encryption System**
- **AES-256-CBC** encryption with PBKDF2 key derivation (10,000 iterations)
- **Multiple file selection** methods:
  - 📁 **Interactive file browser** with visual navigation
  - 📤 **Local file upload** with drag-drop support
  - ⌨️ **Manual path entry** with quick suggestions
- **Secure memory clearing** and random salt/IV generation
- **Real-time validation** and comprehensive error handling

### 🌐 **Network Security Scanner**
- **Real-time packet analysis** (TCP/UDP/ICMP classification)
- **Auto-interface detection** across all platforms (Linux/macOS/Windows)
- **Traffic monitoring** with source/destination IP tracking
- **Port analysis** and comprehensive network statistics
- **JSON-structured output** for API integration

### 📁 **Professional File Management**
- **Server-side file browser** with security validation
- **Directory traversal protection** and path sanitization
- **Visual file/folder navigation** with metadata display
- **Common path shortcuts** (/tmp, /home, /var, etc.)
- **Permission checking** and file type detection

### 🎨 **Cyberpunk Interface**
- **Dark robotics theme** with neon cyber accents
- **Real-time system monitoring** and status displays
- **Professional SOC-inspired** navigation and layouts
- **Responsive design** optimized for security operations
- **Animated cyber effects** and visual feedback

---

## 🚀 **Quick Start**

### **🌐 Online Access (Instant)**
**Live Platform**: **[cybervault.onrender.com](https://cybervault.onrender.com)**
- ✅ No installation required
- ✅ Full functionality available
- ✅ Secure cloud environment

### **💻 Local Development**

#### **System Requirements**
```bash
java -version    # Java 17+
node --version   # Node.js 18+
gcc --version    # GCC compiler
g++ --version    # G++ compiler

# Install dependencies (Ubuntu/Debian)
sudo apt install openjdk-17-jdk maven nodejs npm gcc g++ libssl-dev libpcap-dev

# macOS with Homebrew
brew install openjdk@17 maven node libpcap

# Windows (use WSL2 or install via Chocolatey)
choco install openjdk17 maven nodejs gcc
```

#### **🔧 Setup Steps**
```bash
# 1. Clone repository
git clone https://github.com/arapbett/cybervault.git
cd cybervault

# 2. Compile native security components
gcc -O3 -o backend/c/encrypt backend/c/encrypt.c -lssl -lcrypto
g++ -O3 -o backend/cpp/sniffer backend/cpp/sniffer.cpp -lpcap
chmod +x backend/c/encrypt backend/cpp/sniffer

# 3. Start backend (Terminal 1)
cd backend/java
mvn spring-boot:run
# Backend: http://localhost:8080

# 4. Start frontend (Terminal 2)
cd frontend
npm install && npm start
# Frontend: http://localhost:3000
```

### **🐳 Docker Deployment**
```bash
# Quick Docker setup
docker build -t cybervault:latest .
docker run -p 8080:8080 --cap-add=NET_RAW cybervault:latest

# With docker-compose
docker-compose up -d
```

---

## 📖 **Usage Guide**

### 🔒 **File Encryption (Multiple Methods)**

#### **Method 1: Visual File Browser (Recommended)**
1. Click **🔐 ENCRYPT** tab
2. Click **📁** button next to "Source File Path"
3. Navigate through directories and select your file
4. Click **📂** for output location selection
5. Enter encryption password (8-31 characters)
6. Click **INITIATE ENCRYPTION**

#### **Method 2: File Upload**
1. Click **📤** upload button
2. Drag & drop or select file from your computer
3. File automatically staged for encryption
4. Set output path and password
5. Encrypt

#### **Method 3: Quick Path Selection**
1. Use quick-path buttons (Documents, Downloads, Temp)
2. Or type custom paths manually
3. Set encryption password
4. Process encryption

### 🌐 **Network Security Scanning**
1. Click **🌐 NETWORK** tab
2. Select interface (auto-detect recommended)
3. Choose scan duration (1-60 seconds)
4. Click **START NETWORK SCAN**
5. View comprehensive network analysis:
   - Packet statistics (TCP/UDP/ICMP)
   - Top source/destination IPs
   - Active ports and protocols
   - Network interface status

### 🔓 **File Decryption**
1. Click **🔓 DECRYPT** tab
2. Select encrypted file (.enc) using file browser
3. Choose output location
4. Enter correct decryption password
5. Click **INITIATE DECRYPTION**

---

## 🛠️ **API Documentation**

### **Base Endpoints**
```bash
# Backend API
http://localhost:8080/api/v1/cyber/

# File Browser
GET /files/browse?path=/tmp
GET /files/common-paths

# Security Operations
POST /encrypt
POST /decrypt
GET /network/scan?device=auto&duration=10
GET /status
```

### **Example Usage**
```bash
# File encryption
curl -X POST http://localhost:8080/api/v1/cyber/encrypt \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "input=/tmp/file.txt&output=/tmp/file.enc&key=password123"

# Network scanning
curl "http://localhost:8080/api/v1/cyber/network/scan?device=auto&duration=10"

# File browsing
curl "http://localhost:8080/api/v1/cyber/files/browse?path=/home"
```

---

## 🏗️ **Architecture & Performance**

### **System Architecture**
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   React UI      │    │  Spring Boot    │    │  Native Bins    │
│   Frontend      │◄──►│   Backend       │◄──►│  C/C++ Security │
│   (Port 3000)   │    │   (Port 8080)   │    │  Components     │
└─────────────────┘    └─────────────────┘    └─────────────────┘
        │                        │                        │
        ▼                        ▼                        ▼
┌─────────────────────────────────────────────────────────────────┐
│              Docker Container (Alpine Linux)                    │
│         Production-Ready Security Environment                   │
└─────────────────────────────────────────────────────────────────┘
```

### **Technology Stack**
- **Frontend**: React 18 + Tailwind CSS + Custom Cyber Themes
- **Backend**: Spring Boot 3 + Spring Security 6 + Jakarta Validation
- **Security Core**: C (OpenSSL 3.0) + C++ (libpcap) + Security Hardening
- **Deployment**: Docker + Alpine Linux + Multi-stage Optimization
- **Performance**: < 30s startup, ~50MB/s encryption, < 100ms API response

---

## 🔐 **Enterprise Security Features**

### **🛡️ Encryption Security**
- **AES-256-CBC**: Military-grade encryption standard
- **PBKDF2**: 10,000 iterations key strengthening
- **Random Salt/IV**: Unique per encryption operation
- **Secure Memory**: Automatic clearing of sensitive data
- **Input Validation**: Comprehensive security checks

### **🌐 Network Security**
- **Deep Packet Inspection**: Raw socket access
- **Protocol Classification**: TCP/UDP/ICMP analysis
- **Real-time Monitoring**: Live traffic statistics
- **Multi-interface**: Complete network coverage
- **Security Scanning**: Port and vulnerability detection

### **🏰 Platform Security**
- **Input Sanitization**: XSS & injection prevention
- **Path Traversal Protection**: Directory security
- **Rate Limiting**: DDoS protection ready
- **Container Security**: Non-root execution
- **API Authentication**: Security token ready

---

## 🚀 **Deployment Options**

### **☁️ Cloud Platforms**
- ✅ **Render** (Current: [cybervault.onrender.com](https://cybervault.onrender.com))
- ✅ **AWS ECS/Fargate** - Enterprise container deployment
- ✅ **Google Cloud Run** - Serverless container platform
- ✅ **Azure Container Instances** - Microsoft cloud
- ✅ **Heroku** - Simple PaaS deployment

### **🏠 Self-Hosted**
- ✅ **Docker Compose** - Local orchestration
- ✅ **Kubernetes** - Enterprise orchestration
- ✅ **VPS/Dedicated** - Full control deployment
- ✅ **Local Development** - Development environment

---

## 🤝 **Contributing**

### **Development Process**
1. **Fork** the repository
2. **Create** feature branch (`git checkout -b feature/amazing-feature`)
3. **Compile** and test local binaries
4. **Test** all security features
5. **Commit** changes (`git commit -m 'Add amazing feature'`)
6. **Push** to branch (`git push origin feature/amazing-feature`)
7. **Open** Pull Request with security review

### **Code Standards**
- **Security First**: OWASP compliance required
- **Testing**: 70% minimum coverage
- **Documentation**: Comprehensive API docs
- **Performance**: Benchmark all changes

---

## 📝 **License & Legal**

### **MIT License**
This project is open source under the MIT License - see [LICENSE](LICENSE) file.

### **⚠️ Security Disclaimer**
**Authorized Use Only:**
- ✅ Security research and education
- ✅ Authorized penetration testing
- ✅ CTF competitions and training
- ✅ Defensive security operations
- ✅ Personal file encryption

**Prohibited Uses:**
- ❌ Unauthorized system access
- ❌ Illegal surveillance or monitoring
- ❌ Violation of privacy laws
- ❌ Malicious network activities

---

## 👨‍💻 **Author & Support**

**Arap Bett** - Security Architect & Platform Developer
- 🌐 **Platform**: [cybervault.onrender.com](https://cybervault.onrender.com)
- 📧 **Email**: arap.bett@cybervault.com
- 🐙 **GitHub**: [@arapbett](https://github.com/arapbett)
- 🛠️ **Issues**: [Report bugs or request features](https://github.com/arapbett/cybervault/issues)

---

## 🙏 **Acknowledgments**

- **OpenSSL Foundation** - Cryptographic security libraries
- **libpcap Team** - Network packet analysis framework
- **Spring Framework** - Enterprise Java platform
- **React Community** - Modern web interface framework
- **Alpine Linux** - Secure container base system

---

<div align="center">

**🛡️ Securing the Digital Frontier with Industrial-Grade Cybersecurity 🛡️**

[![Security](https://img.shields.io/badge/Security-First-red?style=flat&logo=shield)](https://cybervault.onrender.com)
[![Performance](https://img.shields.io/badge/Performance-Optimized-green?style=flat&logo=speedtest)](https://cybervault.onrender.com)
[![Platform](https://img.shields.io/badge/Platform-Universal-blue?style=flat&logo=windows)](https://cybervault.onrender.com)

[⭐ Star Repository](https://github.com/arapbett/cybervault) | [🚀 Live Platform](https://cybervault.onrender.com) | [📖 Full Documentation](LOCAL_DEVELOPMENT.md)

</div>
