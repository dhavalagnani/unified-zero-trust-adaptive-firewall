#!/bin/bash
#
# bootstrap.sh
# 
# Purpose: Validate prerequisites and start the Unified Zero-Trust Adaptive Firewall lab
# This script checks for required system dependencies, installs Python packages,
# sets up virtual environments, validates configuration files, and starts all services.
#
# Usage: ./bootstrap.sh [--skip-checks] [--dev-mode]
#
# Context: This is the main entry point for setting up the entire UZTAF system.
# It orchestrates the deployment of PEP (Policy Enforcement Point), correlation engine,
# and agents across the infrastructure.

set -e

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
PYTHON_MIN_VERSION="3.9"
REQUIRED_PACKAGES=("python3" "pip3" "git" "nftables" "ansible" "jq")
SKIP_CHECKS=false
DEV_MODE=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --skip-checks)
            SKIP_CHECKS=true
            shift
            ;;
        --dev-mode)
            DEV_MODE=true
            shift
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--skip-checks] [--dev-mode]"
            exit 1
            ;;
    esac
done

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root (needed for systemd service installation)
check_root() {
    if [[ $EUID -ne 0 ]] && [[ "$SKIP_CHECKS" == false ]]; then
        log_warn "This script should be run as root for full functionality"
        log_warn "Some features may not work without root privileges"
    fi
}

# Validate Python version
check_python_version() {
    log_info "Checking Python version..."
    
    if ! command -v python3 &> /dev/null; then
        log_error "Python 3 is not installed"
        return 1
    fi
    
    PYTHON_VERSION=$(python3 --version | awk '{print $2}')
    log_info "Found Python $PYTHON_VERSION"
    
    # Simple version comparison (works for major.minor)
    REQUIRED_VERSION=$(echo $PYTHON_MIN_VERSION | awk -F. '{print $1*100 + $2}')
    CURRENT_VERSION=$(echo $PYTHON_VERSION | awk -F. '{print $1*100 + $2}')
    
    if [[ $CURRENT_VERSION -lt $REQUIRED_VERSION ]]; then
        log_error "Python version must be >= $PYTHON_MIN_VERSION"
        return 1
    fi
    
    log_info "Python version check passed"
}

# Check for required system packages
check_dependencies() {
    log_info "Checking system dependencies..."
    
    local missing_packages=()
    
    for package in "${REQUIRED_PACKAGES[@]}"; do
        if ! command -v $package &> /dev/null; then
            missing_packages+=($package)
            log_warn "Missing: $package"
        else
            log_info "Found: $package"
        fi
    done
    
    if [[ ${#missing_packages[@]} -gt 0 ]]; then
        log_error "Missing required packages: ${missing_packages[*]}"
        log_info "Install them using: sudo apt-get install ${missing_packages[*]}"
        return 1
    fi
    
    log_info "All system dependencies are installed"
}

# Check if .env file exists
check_env_file() {
    log_info "Checking environment configuration..."
    
    if [[ ! -f ".env" ]]; then
        if [[ -f ".env.example" ]]; then
            log_warn ".env file not found. Copying from .env.example"
            cp .env.example .env
            log_info "Please edit .env file with your configuration"
        else
            log_error ".env.example not found. Cannot create .env file"
            return 1
        fi
    else
        log_info ".env file exists"
    fi
}

# Setup Python virtual environments for each component
setup_venvs() {
    log_info "Setting up Python virtual environments..."
    
    # PEP virtual environment
    if [[ -d "src/pep" ]]; then
        log_info "Setting up PEP virtual environment..."
        cd src/pep
        bash venv_setup.sh
        cd ../..
    fi
    
    # Correlation Engine virtual environment
    if [[ -d "src/correlation" ]]; then
        log_info "Setting up Correlation Engine virtual environment..."
        cd src/correlation
        bash venv_setup.sh
        cd ../..
    fi
    
    # Agent virtual environment
    if [[ -d "src/agent" ]]; then
        log_info "Setting up Agent virtual environment..."
        cd src/agent
        bash venv_setup.sh
        cd ../..
    fi
    
    log_info "Virtual environments setup complete"
}

# Generate certificates if they don't exist
setup_certificates() {
    log_info "Setting up certificates..."
    
    if [[ ! -d "certs" ]]; then
        log_info "Generating certificates..."
        bash scripts/gen-certs.sh
    else
        log_info "Certificates directory already exists"
    fi
}

# Validate Ansible inventory
check_ansible_inventory() {
    log_info "Validating Ansible inventory..."
    
    if [[ -f "infra/ansible/hosts.ini" ]]; then
        ansible-inventory -i infra/ansible/hosts.ini --list > /dev/null 2>&1
        if [[ $? -eq 0 ]]; then
            log_info "Ansible inventory is valid"
        else
            log_error "Ansible inventory validation failed"
            return 1
        fi
    else
        log_warn "Ansible inventory not found at infra/ansible/hosts.ini"
    fi
}

# Install systemd services
install_services() {
    log_info "Installing systemd services..."
    
    if [[ $EUID -ne 0 ]]; then
        log_warn "Skipping systemd service installation (requires root)"
        return 0
    fi
    
    # Install PEP service
    if [[ -f "src/pep/systemd/pep.service" ]]; then
        log_info "Installing PEP service..."
        cp src/pep/systemd/pep.service /etc/systemd/system/
        systemctl daemon-reload
        systemctl enable pep.service
    fi
    
    # Install Correlation Engine service
    if [[ -f "src/correlation/systemd/correlation.service" ]]; then
        log_info "Installing Correlation Engine service..."
        cp src/correlation/systemd/correlation.service /etc/systemd/system/
        systemctl daemon-reload
        systemctl enable correlation.service
    fi
    
    # Install Agent service
    if [[ -f "src/agent/systemd/agent.service" ]]; then
        log_info "Installing Agent service..."
        cp src/agent/systemd/agent.service /etc/systemd/system/
        systemctl daemon-reload
        systemctl enable agent.service
    fi
    
    log_info "Systemd services installed"
}

# Start services
start_services() {
    log_info "Starting services..."
    
    if [[ $EUID -ne 0 ]]; then
        log_warn "Cannot start systemd services without root privileges"
        log_info "Run manually: sudo systemctl start pep correlation agent"
        return 0
    fi
    
    systemctl start pep.service
    systemctl start correlation.service
    systemctl start agent.service
    
    log_info "Services started successfully"
}

# Display service status
show_status() {
    log_info "Service Status:"
    echo "===================="
    
    if command -v systemctl &> /dev/null && [[ $EUID -eq 0 ]]; then
        systemctl status pep.service --no-pager | head -n 5
        echo ""
        systemctl status correlation.service --no-pager | head -n 5
        echo ""
        systemctl status agent.service --no-pager | head -n 5
    else
        log_info "Run 'sudo systemctl status pep correlation agent' to check service status"
    fi
}

# Main execution
main() {
    log_info "Starting Unified Zero-Trust Adaptive Firewall bootstrap..."
    log_info "=================================================="
    
    # Run checks unless skipped
    if [[ "$SKIP_CHECKS" == false ]]; then
        check_root
        check_python_version || exit 1
        check_dependencies || exit 1
        check_env_file || exit 1
        check_ansible_inventory
    else
        log_warn "Skipping prerequisite checks"
    fi
    
    # Setup components
    setup_certificates
    setup_venvs
    
    # Install and start services (if not in dev mode)
    if [[ "$DEV_MODE" == false ]]; then
        install_services
        start_services
        show_status
    else
        log_info "Dev mode: Skipping service installation and startup"
        log_info "Run services manually for development"
    fi
    
    log_info "=================================================="
    log_info "Bootstrap complete!"
    log_info ""
    log_info "Next steps:"
    log_info "1. Configure Keycloak (see infra/keycloak/install_keycloak.md)"
    log_info "2. Review and update configuration files"
    log_info "3. Run integration tests: bash tests/integration/test_quarantine_flow.sh"
    log_info "4. Check documentation in docs/ folder"
}

main
