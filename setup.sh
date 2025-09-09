#!/bin/bash

# Elbanna Recon v1.0 - Linux/macOS Setup Script
# Author: Yousef Osama - Cybersecurity Engineering, Egyptian Chinese University
# Last Updated: September 8, 2025

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# ASCII Banner
echo -e "${PURPLE}"
echo "================================================================================"
echo " _____ _     ____    _    _   _ _   _    _    ____  _____ ____ ___  _   _ "
echo "| ____| |   | __ )  / \  | \ | | \ | |  / \  |  _ \| ____/ ___/ _ \| \ | |"
echo "|  _| | |   |  _ \ / _ \ |  \| |  \| | / _ \ | |_) |  _|| |  | | | |  \| |"
echo "| |___| |___| |_) / ___ \| |\  | |\  |/ ___ \|  _ <| |__| |__| |_| | |\  |"
echo "|_____|_____|____/_/   \_\_| \_|_| \_/_/   \_\_| \_\_____\____\___/|_| \_|"
echo ""
echo "                         v1.0 Setup Script"
echo "         Yousef Osama - Cybersecurity Engineering ECU"
echo "================================================================================"
echo -e "${NC}"

# Function to print colored messages
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if Python 3 is installed
print_status "Checking Python 3 installation..."
if ! command -v python3 &> /dev/null; then
    print_error "Python 3 is not installed. Please install Python 3.8+ first."
    echo "Visit: https://www.python.org/downloads/"
    exit 1
fi

PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
print_success "Python $PYTHON_VERSION found"

# Check if pip is available
print_status "Checking pip installation..."
if ! python3 -m pip --version &> /dev/null; then
    print_error "pip is not available. Please install pip first."
    exit 1
fi
print_success "pip is available"

# Check if we're in the correct directory
if [ ! -f "elbanna_recon.py" ]; then
    print_error "elbanna_recon.py not found. Please run this script from the project root directory."
    exit 1
fi

# Step 1: Create virtual environment
print_status "Creating Python virtual environment..."
if [ -d "venv" ]; then
    print_warning "Virtual environment already exists. Removing old one..."
    rm -rf venv
fi

python3 -m venv venv
if [ $? -eq 0 ]; then
    print_success "Virtual environment created successfully"
else
    print_error "Failed to create virtual environment"
    exit 1
fi

# Step 2: Activate virtual environment
print_status "Activating virtual environment..."
source venv/bin/activate
if [ $? -eq 0 ]; then
    print_success "Virtual environment activated"
else
    print_error "Failed to activate virtual environment"
    exit 1
fi

# Step 3: Upgrade pip
print_status "Upgrading pip to latest version..."
python -m pip install --upgrade pip
if [ $? -eq 0 ]; then
    print_success "pip upgraded successfully"
else
    print_warning "pip upgrade failed, continuing with current version"
fi

# Step 4: Install dependencies
print_status "Installing dependencies from requirements.txt..."
echo -e "${CYAN}This may take a few minutes...${NC}"

pip install -r requirements.txt
if [ $? -eq 0 ]; then
    print_success "All dependencies installed successfully"
else
    print_error "Failed to install some dependencies"
    print_warning "You may need to install system dependencies for some packages"
    echo "For scapy on Linux: sudo apt-get install tcpdump libpcap-dev"
    echo "For scapy on macOS: brew install libpcap"
fi

# Step 5: Create necessary directories
print_status "Creating project directories..."
mkdir -p logs reports tests modules Output Tools
print_success "Project directories created"

# Step 6: Set permissions for network tools (if needed)
print_status "Checking network tool permissions..."
if command -v getcap &> /dev/null; then
    # Check if Python has network capabilities
    PYTHON_PATH=$(which python)
    if ! getcap "$PYTHON_PATH" | grep -q cap_net_raw; then
        print_warning "Network tools may require elevated privileges"
        echo "To enable network packet capture without sudo:"
        echo "sudo setcap cap_net_raw,cap_net_admin+eip $PYTHON_PATH"
        echo ""
        echo "Or run with sudo when using packet capture features"
    fi
fi

# Step 7: Final instructions
echo ""
echo -e "${GREEN}================================================================================"
echo "                         SETUP COMPLETED SUCCESSFULLY!"
echo "================================================================================${NC}"
echo ""
echo -e "${YELLOW}🚀 QUICK START:${NC}"
echo "1. Activate the virtual environment:"
echo -e "   ${CYAN}source venv/bin/activate${NC}"
echo ""
echo "2. Run Elbanna Recon:"
echo -e "   ${CYAN}python elbanna_recon.py${NC}"
echo ""
echo "3. When finished, deactivate the environment:"
echo -e "   ${CYAN}deactivate${NC}"
echo ""
echo -e "${YELLOW}📋 IMPORTANT NOTES:${NC}"
echo "• Some tools require elevated privileges (sudo) for network operations"
echo "• This tool is for educational and authorized testing only"
echo "• Always ensure you have permission before scanning any targets"
echo "• Check local laws and regulations regarding security testing"
echo ""
echo -e "${YELLOW}📚 DOCUMENTATION:${NC}"
echo "• Read README.md for detailed usage instructions"
echo "• Check config.yaml for configuration options"
echo "• View logs/ directory for operation logs"
echo "• Reports are saved in reports/ directory"
echo ""
echo -e "${PURPLE}Author: Yousef Osama - Cybersecurity Engineering${NC}"
echo -e "${PURPLE}Egyptian Chinese University${NC}"
echo ""
echo -e "${RED}⚠️  DISCLAIMER: For educational and authorized security testing only${NC}"
echo "================================================================================"
