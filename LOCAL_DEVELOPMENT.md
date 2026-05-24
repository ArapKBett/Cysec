# 🚀 CyberVault Local Development Setup

This guide will help you run the entire CyberVault platform locally on your machine with full functionality.

## Prerequisites

Ensure you have the following installed:

```bash
# Check versions
java -version    # Need Java 17+
node --version   # Need Node.js 18+
npm --version    # Need npm 9+
gcc --version    # Need GCC for compiling C/C++
g++ --version    # Need G++ for compiling C++

# Install missing dependencies (Ubuntu/Debian)
sudo apt update
sudo apt install openjdk-17-jdk maven nodejs npm gcc g++ libssl-dev libpcap-dev

# Or on macOS with Homebrew
brew install openjdk@17 maven node gcc libpcap

# Or on Windows with Chocolatey
choco install openjdk17 maven nodejs gcc
```

## 🔧 Step 1: Compile Native Binaries

First, compile the C and C++ components for your local system:

```bash
# Navigate to project root
cd /home/arap/ACV

# Compile C encryption module
gcc -O3 -D_FORTIFY_SOURCE=2 -fstack-protector-strong \
    -o backend/c/encrypt \
    backend/c/encrypt.c \
    -lssl -lcrypto

# Compile C++ network sniffer
g++ -O3 -D_FORTIFY_SOURCE=2 -fstack-protector-strong \
    -o backend/cpp/sniffer \
    backend/cpp/sniffer.cpp \
    -lpcap

# Make executables
chmod +x backend/c/encrypt backend/cpp/sniffer

# Test binaries
./backend/c/encrypt
./backend/cpp/sniffer auto 5  # May need sudo for packet capture
```

## 🖥️ Step 2: Start Backend (Java Spring Boot)

```bash
# Navigate to Java backend
cd backend/java

# Install dependencies and compile
mvn clean compile

# Run the backend server
mvn spring-boot:run

# Alternative: Build JAR and run
mvn clean package -DskipTests
java -jar target/cybervault-platform.jar

# Backend will be available at: http://localhost:8080
# API endpoints: http://localhost:8080/api/v1/cyber/*
```

## 🌐 Step 3: Start Frontend (React)

Open a new terminal:

```bash
# Navigate to React frontend
cd frontend

# Install dependencies
npm install

# Start development server
npm start

# Frontend will be available at: http://localhost:3000
# It will proxy API calls to the backend at :8080
```

## 🔧 Step 4: Test Full Functionality

### Test Encryption
```bash
# Create test file
echo "This is sensitive data" > /tmp/test.txt

# Test encryption via API
curl -X POST http://localhost:8080/api/v1/cyber/encrypt \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "input=/tmp/test.txt&output=/tmp/test.enc&key=mypassword123"

# Test decryption
curl -X POST http://localhost:8080/api/v1/cyber/decrypt \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "input=/tmp/test.enc&output=/tmp/test_dec.txt&key=mypassword123"
```

### Test Network Scanner
```bash
# Test network scanning (may require sudo)
curl "http://localhost:8080/api/v1/cyber/network/scan?device=auto&duration=5"
```

### Test File Browser
```bash
# Test file browsing
curl "http://localhost:8080/api/v1/cyber/files/browse?path=/tmp"

# Get common paths
curl "http://localhost:8080/api/v1/cyber/files/common-paths"
```

## 🛠️ Development Commands

### Backend Development
```bash
# Run with hot reload
cd backend/java
mvn spring-boot:run -Dspring-boot.run.jvmArguments="-Dspring.profiles.active=dev"

# Run tests
mvn test

# Package for production
mvn clean package -Pproduction
```

### Frontend Development
```bash
# Run with hot reload (default)
npm start

# Build for production
npm run build:prod

# Run tests
npm test

# Lint code
npm run lint
```

## 🌐 Access Points

When running locally:

- **Frontend UI**: http://localhost:3000
- **Backend API**: http://localhost:8080
- **API Status**: http://localhost:8080/api/v1/cyber/status
- **Health Check**: http://localhost:8080/actuator/health

## 📁 File Browser Usage

The file browser will work with your local file system:

- **Browse**: Click 📁 button to navigate folders
- **Upload**: Click 📤 button to select files
- **Common paths**: Use quick buttons for /tmp, /home, etc.
- **Custom paths**: Type paths manually

## 🌐 Network Scanner Usage

For network scanning to work locally:

```bash
# May need elevated privileges
sudo ./backend/cpp/sniffer auto 10

# Or run backend with sudo (not recommended for production)
sudo mvn spring-boot:run
```

## 🐛 Troubleshooting

### Port Already in Use
```bash
# Kill process on port 8080
sudo lsof -ti:8080 | xargs kill -9

# Kill process on port 3000
sudo lsof -ti:3000 | xargs kill -9
```

### Permission Issues
```bash
# For network scanning
sudo setcap cap_net_raw,cap_net_admin=eip backend/cpp/sniffer

# For file access
chmod 755 backend/c/encrypt backend/cpp/sniffer
```

### Missing Dependencies
```bash
# Ubuntu/Debian
sudo apt install build-essential libssl-dev libpcap-dev

# macOS
brew install openssl libpcap

# Update PATH if needed
export PATH="/usr/local/opt/openjdk@17/bin:$PATH"
```

## 🚀 Production Build

To build everything for production:

```bash
# Build frontend
cd frontend && npm run build:prod

# Copy build to backend resources
cp -r build/* ../backend/java/src/main/resources/static/

# Build backend JAR
cd ../backend/java && mvn clean package -DskipTests

# Run production JAR
java -jar target/cybervault-platform.jar
```

## 🔐 Security Notes

- Network scanning requires elevated privileges
- File browser has path traversal protection
- All APIs include input validation
- Use HTTPS in production
- Configure proper CORS origins

---

This setup gives you full local development with hot reload, debugging, and complete functionality!