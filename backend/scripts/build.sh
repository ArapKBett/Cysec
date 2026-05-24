#!/bin/bash

# CyberVault Security Platform - Build Script v2.0
# Comprehensive build system for all components

set -euo pipefail

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Build configuration
BUILD_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LOG_FILE="${BUILD_DIR}/build.log"
TIMESTAMP=$(date "+%Y-%m-%d %H:%M:%S")

# Security compilation flags
SECURITY_FLAGS="-O2 -D_FORTIFY_SOURCE=2 -fstack-protector-strong -Wl,-z,relro,-z,now"
C_FLAGS="-Wall -Wextra -Werror ${SECURITY_FLAGS}"
CPP_FLAGS="-Wall -Wextra -Werror ${SECURITY_FLAGS}"

# Initialize log
echo "=== CyberVault Build Log - ${TIMESTAMP} ===" > "${LOG_FILE}"

# Utility functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1" | tee -a "${LOG_FILE}"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1" | tee -a "${LOG_FILE}"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "${LOG_FILE}"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "${LOG_FILE}"
}

log_stage() {
    echo -e "\n${CYAN}=== $1 ===${NC}" | tee -a "${LOG_FILE}"
}

check_prerequisites() {
    log_stage "CHECKING PREREQUISITES"

    local missing_deps=()

    # Check C compiler
    if ! command -v gcc >/dev/null 2>&1; then
        missing_deps+=("gcc")
    else
        log_info "✓ GCC found: $(gcc --version | head -n1)"
    fi

    # Check C++ compiler
    if ! command -v g++ >/dev/null 2>&1; then
        missing_deps+=("g++")
    else
        log_info "✓ G++ found: $(g++ --version | head -n1)"
    fi

    # Check Java
    if ! command -v java >/dev/null 2>&1; then
        missing_deps+=("java")
    else
        log_info "✓ Java found: $(java -version 2>&1 | head -n1)"
    fi

    # Check Maven
    if ! command -v mvn >/dev/null 2>&1; then
        missing_deps+=("maven")
    else
        log_info "✓ Maven found: $(mvn --version | head -n1)"
    fi

    # Check Node.js
    if ! command -v node >/dev/null 2>&1; then
        missing_deps+=("nodejs")
    else
        log_info "✓ Node.js found: $(node --version)"
    fi

    # Check npm
    if ! command -v npm >/dev/null 2>&1; then
        missing_deps+=("npm")
    else
        log_info "✓ npm found: $(npm --version)"
    fi

    # Check OpenSSL development headers
    if ! pkg-config --exists openssl; then
        missing_deps+=("libssl-dev/openssl-dev")
    else
        log_info "✓ OpenSSL development libraries found"
    fi

    # Check libpcap development headers
    if ! pkg-config --exists libpcap; then
        missing_deps+=("libpcap-dev")
    else
        log_info "✓ libpcap development libraries found"
    fi

    if [ ${#missing_deps[@]} -ne 0 ]; then
        log_error "Missing dependencies: ${missing_deps[*]}"
        log_error "Please install missing dependencies and try again"
        exit 1
    fi

    log_success "All prerequisites satisfied"
}

build_c_component() {
    log_stage "BUILDING C ENCRYPTION MODULE"

    local src_file="${BUILD_DIR}/backend/c/encrypt.c"
    local output_file="${BUILD_DIR}/backend/c/encrypt"

    if [[ ! -f "${src_file}" ]]; then
        log_error "Source file not found: ${src_file}"
        return 1
    fi

    log_info "Compiling C encryption module with security flags..."
    log_info "Command: gcc ${C_FLAGS} -o ${output_file} ${src_file} -lssl -lcrypto"

    if gcc ${C_FLAGS} -o "${output_file}" "${src_file}" -lssl -lcrypto 2>>"${LOG_FILE}"; then
        chmod +x "${output_file}"
        log_success "C encryption module built successfully"
        log_info "Binary: ${output_file}"
        log_info "Size: $(du -h "${output_file}" | cut -f1)"
        return 0
    else
        log_error "C compilation failed. Check ${LOG_FILE} for details"
        return 1
    fi
}

build_cpp_component() {
    log_stage "BUILDING C++ NETWORK SNIFFER"

    local src_file="${BUILD_DIR}/backend/cpp/sniffer.cpp"
    local output_file="${BUILD_DIR}/backend/cpp/sniffer"

    if [[ ! -f "${src_file}" ]]; then
        log_error "Source file not found: ${src_file}"
        return 1
    fi

    log_info "Compiling C++ network sniffer with security flags..."
    log_info "Command: g++ ${CPP_FLAGS} -o ${output_file} ${src_file} -lpcap"

    if g++ ${CPP_FLAGS} -o "${output_file}" "${src_file}" -lpcap 2>>"${LOG_FILE}"; then
        chmod +x "${output_file}"
        log_success "C++ network sniffer built successfully"
        log_info "Binary: ${output_file}"
        log_info "Size: $(du -h "${output_file}" | cut -f1)"
        return 0
    else
        log_error "C++ compilation failed. Check ${LOG_FILE} for details"
        return 1
    fi
}

build_java_backend() {
    log_stage "BUILDING JAVA BACKEND"

    local java_dir="${BUILD_DIR}/backend/java"

    if [[ ! -f "${java_dir}/pom.xml" ]]; then
        log_error "Maven POM file not found: ${java_dir}/pom.xml"
        return 1
    fi

    log_info "Building Spring Boot application..."

    cd "${java_dir}"

    # Clean and compile
    if mvn clean compile 2>>"${LOG_FILE}"; then
        log_success "Java compilation successful"
    else
        log_error "Java compilation failed"
        cd "${BUILD_DIR}"
        return 1
    fi

    # Run tests
    log_info "Running unit tests..."
    if mvn test 2>>"${LOG_FILE}"; then
        log_success "All tests passed"
    else
        log_warning "Some tests failed. Check logs for details"
    fi

    # Package application
    log_info "Packaging application..."
    if mvn package -DskipTests 2>>"${LOG_FILE}"; then
        local jar_file=$(find target -name "*.jar" -not -name "*sources.jar" -not -name "*javadoc.jar" | head -n1)
        if [[ -n "${jar_file}" ]]; then
            log_success "Java backend built successfully"
            log_info "JAR: ${jar_file}"
            log_info "Size: $(du -h "${jar_file}" | cut -f1)"
        else
            log_error "JAR file not found after build"
            cd "${BUILD_DIR}"
            return 1
        fi
    else
        log_error "Java packaging failed"
        cd "${BUILD_DIR}"
        return 1
    fi

    cd "${BUILD_DIR}"
    return 0
}

build_frontend() {
    log_stage "BUILDING REACT FRONTEND"

    local frontend_dir="${BUILD_DIR}/frontend"

    if [[ ! -f "${frontend_dir}/package.json" ]]; then
        log_error "Package.json not found: ${frontend_dir}/package.json"
        return 1
    fi

    cd "${frontend_dir}"

    # Install dependencies
    log_info "Installing Node.js dependencies..."
    if npm ci --production=false 2>>"${LOG_FILE}"; then
        log_success "Dependencies installed successfully"
    else
        log_error "Failed to install dependencies"
        cd "${BUILD_DIR}"
        return 1
    fi

    # Security audit
    log_info "Running security audit..."
    npm audit --audit-level=high 2>>"${LOG_FILE}" || log_warning "Security vulnerabilities detected"

    # Build production bundle
    log_info "Building production bundle..."
    if npm run build:prod 2>>"${LOG_FILE}"; then
        if [[ -d "build" ]]; then
            log_success "Frontend built successfully"
            log_info "Build directory: ${frontend_dir}/build"
            log_info "Size: $(du -sh build | cut -f1)"
        else
            log_error "Build directory not found"
            cd "${BUILD_DIR}"
            return 1
        fi
    else
        log_error "Frontend build failed"
        cd "${BUILD_DIR}"
        return 1
    fi

    cd "${BUILD_DIR}"
    return 0
}

create_build_summary() {
    log_stage "BUILD SUMMARY"

    local c_binary="${BUILD_DIR}/backend/c/encrypt"
    local cpp_binary="${BUILD_DIR}/backend/cpp/sniffer"
    local java_jar="${BUILD_DIR}/backend/java/target/cybervault-platform.jar"
    local frontend_build="${BUILD_DIR}/frontend/build"

    echo -e "\n${CYAN}Component Status:${NC}"

    if [[ -x "${c_binary}" ]]; then
        echo -e "  ${GREEN}✓${NC} C Encryption Module: ${c_binary}"
    else
        echo -e "  ${RED}✗${NC} C Encryption Module: Missing"
    fi

    if [[ -x "${cpp_binary}" ]]; then
        echo -e "  ${GREEN}✓${NC} C++ Network Sniffer: ${cpp_binary}"
    else
        echo -e "  ${RED}✗${NC} C++ Network Sniffer: Missing"
    fi

    if [[ -f "${java_jar}" ]]; then
        echo -e "  ${GREEN}✓${NC} Java Backend: ${java_jar}"
    else
        echo -e "  ${RED}✗${NC} Java Backend: Missing"
    fi

    if [[ -d "${frontend_build}" ]]; then
        echo -e "  ${GREEN}✓${NC} React Frontend: ${frontend_build}"
    else
        echo -e "  ${RED}✗${NC} React Frontend: Missing"
    fi

    echo -e "\n${CYAN}Next Steps:${NC}"
    echo "  1. Run backend: cd backend/java && mvn spring-boot:run"
    echo "  2. Or use Docker: docker build -t cybervault:latest ."
    echo "  3. Access UI: http://localhost:8080/cybervault"
}

cleanup() {
    log_info "Cleaning up temporary files..."
    # Clean Maven cache if needed
    # Clean npm cache if needed
}

main() {
    log_stage "CYBERVAULT SECURITY PLATFORM BUILD"
    log_info "Build started at: ${TIMESTAMP}"
    log_info "Build directory: ${BUILD_DIR}"
    log_info "Log file: ${LOG_FILE}"

    # Trap for cleanup
    trap cleanup EXIT

    # Run build pipeline
    check_prerequisites
    build_c_component || exit 1
    build_cpp_component || exit 1
    build_java_backend || exit 1
    build_frontend || exit 1

    create_build_summary

    local end_time=$(date "+%Y-%m-%d %H:%M:%S")
    log_success "Build completed successfully at: ${end_time}"

    echo -e "\n${GREEN}🛡️  CyberVault Security Platform is ready for deployment! 🛡️${NC}"
}

# Run main function
main "$@"
