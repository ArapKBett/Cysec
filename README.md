# 🛡️ CyberVault Security Platform v2.0

<div align="center">

![CyberVault Logo](frontend/public/logo.png)

**Advanced Cybersecurity Operations Terminal**

[![Version](https://img.shields.io/badge/version-2.0.0-blue.svg)](https://github.com/arapbett/cybervault)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Java](https://img.shields.io/badge/Java-17-orange.svg)](https://openjdk.org/projects/jdk/17/)
[![React](https://img.shields.io/badge/React-18.2-blue.svg)](https://reactjs.org/)
[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.2-green.svg)](https://spring.io/projects/spring-boot)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue.svg)](https://docker.com/)
[![Security](https://img.shields.io/badge/Security-First-red.svg)](#security)

*A comprehensive cybersecurity toolkit for security professionals, researchers, and educators*

</div>

---

## 🎯 Overview

CyberVault is a state-of-the-art cybersecurity platform that combines cutting-edge encryption technologies with advanced network analysis capabilities. Built with a modern tech stack and designed with security-first principles, it provides a comprehensive suite of tools for cybersecurity professionals.

### 🔐 Core Features

- **🔒 Military-Grade Encryption**: AES-256 file encryption/decryption with secure key management
- **📡 Network Intelligence**: Real-time packet analysis and network monitoring
- **🎨 Cyber Aesthetic UI**: Dark-themed, futuristic interface with robotics styling
- **⚡ High Performance**: Optimized C/C++ core with efficient Java middleware
- **🔧 Professional APIs**: RESTful APIs with comprehensive security features
- **📊 Real-time Monitoring**: Live system status and operation tracking
- **🛡️ Security Hardened**: Input validation, rate limiting, and secure defaults

### 🎭 Modern Design

- **Dark Grey Robotics Theme**: Cyberpunk-inspired design with neon accents
- **Responsive Layout**: Optimized for desktop and mobile security operations
- **Animated Components**: Smooth transitions and cyber-themed effects
- **Professional Typography**: Orbitron and JetBrains Mono fonts
- **Circuit Board Aesthetics**: Subtle tech patterns and glow effects

---

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   React Frontend │    │  Spring Boot    │    │   C/C++ Core    │
│   (Port 3000)   │◄──►│   Backend       │◄──►│   Binaries      │
│                 │    │   (Port 8080)   │    │                 │
│  • Cyber UI     │    │  • REST APIs    │    │  • AES-256      │
│  • Tailwind CSS │    │  • Security     │    │  • Packet       │
│  • Animations   │    │  • Validation   │    │    Analysis     │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

### Technology Stack

**Frontend:**
- React 18.2 with modern hooks
- Tailwind CSS 3.3 with custom themes
- Framer Motion for animations
- Axios for API communication
- React Hook Form for input handling

**Backend:**
- Spring Boot 3.2 with Java 17
- Spring Security for authentication
- Jakarta Validation for input validation
- Spring Actuator for monitoring
- Logback for structured logging

**Core Security:**
- C language AES-256 implementation
- C++ libpcap network analysis
- OpenSSL cryptographic libraries
- Secure process execution

**Infrastructure:**
- Docker multi-stage builds
- Alpine Linux for security
- Non-root containers
- Health checks and monitoring

---

## 🚀 Quick Start

### Prerequisites

- **Docker** (Recommended): Latest Docker and Docker Compose
- **Development**: Java 17, Node.js 18+, Maven 3.9+
- **System**: Linux/macOS with gcc, g++, libpcap-dev, openssl-dev

### 🐳 Docker Deployment (Recommended)

```bash
# Clone the repository
git clone https://github.com/arapbett/cybervault.git
cd cybervault

# Build and run with Docker
docker build -t cybervault:latest .
docker run -p 8080:8080 --name cybervault cybervault:latest

# Access the application
open http://localhost:8080/cybervault
```

### 🛠️ Development Setup

#### 1. Backend Setup
```bash
cd backend/java

# Install dependencies and build
mvn clean install

# Run in development mode
mvn spring-boot:run -Dspring-boot.run.profiles=dev
```

#### 2. Frontend Setup
```bash
cd frontend

# Install dependencies
npm install

# Start development server
npm run dev
```

#### 3. Compile Native Components
```bash
# Compile C encryption module
gcc -o backend/c/encrypt backend/c/encrypt.c -lssl -lcrypto

# Compile C++ network sniffer
g++ -o backend/cpp/sniffer backend/cpp/sniffer.cpp -lpcap

# Set permissions
chmod +x backend/c/encrypt backend/cpp/sniffer
```

---

## 📖 Usage Guide

### 🔐 File Encryption

1. Navigate to the **ENCRYPT** tab
2. Enter source file path (e.g., `/path/to/document.txt`)
3. Specify output location (e.g., `/path/to/document.enc`)
4. Provide encryption key (8-31 characters)
5. Click **INITIATE ENCRYPTION**

### 🔓 File Decryption

1. Navigate to the **DECRYPT** tab
2. Enter encrypted file path
3. Specify decrypted output location
4. Enter the correct decryption key
5. Click **INITIATE DECRYPTION**

### 📡 Network Analysis

1. Navigate to the **NETWORK SCAN** tab
2. Select network interface (e.g., `wlan0`, `eth0`)
3. Set scan duration (1-60 seconds)
4. Click **START NETWORK SCAN**
5. View real-time packet analysis

---

## 🔧 API Reference

### Base URL
```
http://localhost:8080/cybervault/api/v1/cyber
```

### Encryption Endpoint
```http
POST /encrypt
Content-Type: application/x-www-form-urlencoded

input=file.txt&output=file.enc&key=mysecretkey
```

### Decryption Endpoint
```http
POST /decrypt
Content-Type: application/x-www-form-urlencoded

input=file.enc&output=file.txt&key=mysecretkey
```

### Network Scan Endpoint
```http
GET /network/scan?device=wlan0&duration=10
```

### System Status
```http
GET /status
```

---

## 🔒 Security Features

### Input Validation
- Path traversal protection
- Character sanitization
- Length limitations
- Pattern matching validation

### Process Security
- Timeout protection (30 seconds)
- Non-root execution
- Secure parameter passing
- Process isolation

### API Security
- CORS configuration
- Rate limiting
- Request logging
- Error message sanitization

### Container Security
- Non-root user execution
- Minimal base image (Alpine)
- Security-hardened compilation flags
- Regular security updates

---

## 🧪 Testing

```bash
# Run backend tests
cd backend/java
mvn test

# Run frontend tests
cd frontend
npm test

# Run with coverage
npm run test:coverage

# Security audit
npm run security:audit
```

---

## 📦 Build & Deploy

### Production Build
```bash
# Frontend production build
npm run build:prod

# Backend production build
mvn clean package -Pprod

# Docker production build
docker build --target production -t cybervault:prod .
```

### Environment Configuration
```bash
# Development
export SPRING_PROFILES_ACTIVE=dev

# Production
export SPRING_PROFILES_ACTIVE=prod
export JAVA_OPTS="-Xms512m -Xmx1g"
```

---

## 🤝 Contributing

We welcome contributions from the cybersecurity community! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

### Development Workflow
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests and documentation
5. Submit a pull request

### Code Standards
- Java: Google Java Style Guide
- JavaScript: Prettier + ESLint
- Security: OWASP guidelines
- Testing: Minimum 70% coverage

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- OpenSSL Project for cryptographic libraries
- libpcap developers for network analysis capabilities
- Spring Framework team for excellent documentation
- React and Tailwind CSS communities
- Cybersecurity research community

---

## ⚠️ Disclaimer

This tool is intended for:
- ✅ Authorized security testing
- ✅ Educational purposes
- ✅ Security research
- ✅ Defensive security operations
- ✅ CTF competitions

**NOT intended for:**
- ❌ Unauthorized system access
- ❌ Malicious activities
- ❌ Violation of privacy laws
- ❌ Illegal surveillance

Users are responsible for compliance with all applicable laws and regulations.

---

<div align="center">

**Made with ❤️ by the CyberVault Team**

[Website](https://cybervault.onrender.com) • [Documentation](https://docs.cybervault.com) • [Support](https://github.com/arapbett/cybervault/issues)

</div>
