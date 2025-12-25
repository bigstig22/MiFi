#!/bin/bash

###############################################################################
# MiFi Automated Setup Script
# This script automates the installation and setup of MiFi and all dependencies
###############################################################################

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Error tracking
ERRORS=0
WARNINGS=0

# Function to print colored output
print_status() {
    echo -e "${GREEN}[*]${NC} $1"
}

print_error() {
    echo -e "${RED}[!] ERROR:${NC} $1" >&2
    ((ERRORS++))
}

print_warning() {
    echo -e "${YELLOW}[!] WARNING:${NC} $1" >&2
    ((WARNINGS++))
}

print_info() {
    echo -e "${BLUE}[i]${NC} $1"
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to check if running as root
check_root() {
    if [ "$EUID" -eq 0 ]; then
        print_error "This script should NOT be run as root/sudo. It will prompt for sudo when needed."
        exit 1
    fi
}

# Function to create directories
create_directories() {
    print_status "Creating necessary directories..."
    
    DIRS=("logs" "collection" "archive/pcap" "tracking" "john/results" "john/archive" "hc/archive")
    
    for dir in "${DIRS[@]}"; do
        if [ ! -d "$dir" ]; then
            mkdir -p "$dir"
            print_info "Created directory: $dir"
        else
            print_info "Directory already exists: $dir"
        fi
    done
}

# Function to detect Linux distribution
detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO=$ID
        VERSION=$VERSION_ID
    else
        print_error "Cannot detect Linux distribution"
        exit 1
    fi
}

# Function to install system packages
install_system_packages() {
    print_status "Installing system packages (this may require sudo)..."
    
    detect_distro
    
    case $DISTRO in
        ubuntu|debian)
            PACKAGES=(
                "aircrack-ng"
                "john"
                "hashcat"
                "python3"
                "python3-pip"
                "gpsd"
                "gpsd-clients"
                "iw"
                "wireless-tools"
            )
            
            print_info "Detected: $DISTRO $VERSION"
            print_info "Updating package lists..."
            sudo apt-get update || {
                print_error "Failed to update package lists"
                return 1
            }
            
            MISSING_PACKAGES=()
            for pkg in "${PACKAGES[@]}"; do
                if ! dpkg -l | grep -q "^ii  $pkg "; then
                    MISSING_PACKAGES+=("$pkg")
                fi
            done
            
            if [ ${#MISSING_PACKAGES[@]} -eq 0 ]; then
                print_status "All required packages are already installed"
            else
                print_info "Installing missing packages: ${MISSING_PACKAGES[*]}"
                sudo apt-get install -y "${MISSING_PACKAGES[@]}" || {
                    print_error "Failed to install packages"
                    return 1
                }
            fi
            ;;
        fedora|rhel|centos)
            PACKAGES=(
                "aircrack-ng"
                "john"
                "hashcat"
                "python3"
                "python3-pip"
                "gpsd"
                "gpsd-clients"
                "iw"
                "wireless-tools"
            )
            
            print_info "Detected: $DISTRO $VERSION"
            print_info "Installing packages..."
            sudo dnf install -y "${PACKAGES[@]}" || {
                print_error "Failed to install packages"
                return 1
            }
            ;;
        arch|manjaro)
            PACKAGES=(
                "aircrack-ng"
                "john"
                "hashcat"
                "python"
                "python-pip"
                "gpsd"
                "iw"
                "wireless_tools"
            )
            
            print_info "Detected: $DISTRO"
            print_info "Installing packages..."
            sudo pacman -S --noconfirm "${PACKAGES[@]}" || {
                print_error "Failed to install packages"
                return 1
            }
            ;;
        *)
            print_warning "Unsupported distribution: $DISTRO"
            print_info "Please manually install: aircrack-ng, john, hashcat, python3, gpsd, gpsd-clients, iw, wireless-tools"
            return 1
            ;;
    esac
    
    print_status "System packages installed successfully"
    return 0
}

# Function to install Python packages
install_python_packages() {
    print_status "Installing Python dependencies..."
    
    if ! command_exists python3; then
        print_error "python3 is not installed"
        return 1
    fi
    
    if ! command_exists pip3; then
        print_warning "pip3 not found, attempting to install..."
        detect_distro
        case $DISTRO in
            ubuntu|debian)
                sudo apt-get install -y python3-pip || {
                    print_error "Failed to install pip3"
                    return 1
                }
                ;;
            fedora|rhel|centos)
                sudo dnf install -y python3-pip || {
                    print_error "Failed to install pip3"
                    return 1
                }
                ;;
            arch|manjaro)
                sudo pacman -S --noconfirm python-pip || {
                    print_error "Failed to install pip3"
                    return 1
                }
                ;;
            *)
                print_error "Please install pip3 manually for your distribution"
                return 1
                ;;
        esac
    fi
    
    print_info "Upgrading pip..."
    python3 -m pip install --user --upgrade pip || {
        print_warning "Failed to upgrade pip, continuing anyway..."
    }
    
    print_info "Installing Python packages from requirements.txt..."
    python3 -m pip install --user -r requirements.txt || {
        print_error "Failed to install Python packages"
        return 1
    }
    
    print_status "Python packages installed successfully"
    return 0
}

# Function to download rockyou.txt
download_rockyou() {
    print_status "Checking for rockyou.txt wordlist..."
    
    if [ -f "rockyou.txt" ]; then
        print_info "rockyou.txt already exists"
        return 0
    fi
    
    print_info "Downloading rockyou.txt wordlist..."
    
    # Try multiple sources
    ROCKYOU_URLS=(
        "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt"
        "https://www.scrapmaker.com/data/wordlists/dictionaries/rockyou.txt"
    )
    
    for url in "${ROCKYOU_URLS[@]}"; do
        print_info "Trying: $url"
        if wget -q --show-progress -O rockyou.txt "$url" 2>/dev/null || \
           curl -L -o rockyou.txt "$url" 2>/dev/null; then
            if [ -f "rockyou.txt" ] && [ -s "rockyou.txt" ]; then
                print_status "Successfully downloaded rockyou.txt"
                return 0
            fi
        fi
    done
    
    print_warning "Failed to download rockyou.txt automatically"
    print_info "You can download it manually from:"
    print_info "  https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt"
    print_info "  Or extract from: /usr/share/wordlists/rockyou.txt.gz (if available)"
    
    # Try to extract from system location
    if [ -f "/usr/share/wordlists/rockyou.txt.gz" ]; then
        print_info "Found system rockyou.txt.gz, extracting..."
        gunzip -c /usr/share/wordlists/rockyou.txt.gz > rockyou.txt 2>/dev/null && {
            print_status "Extracted rockyou.txt from system location"
            return 0
        }
    fi
    
    return 1
}

# Function to setup GPS
setup_gps() {
    print_status "Setting up GPS (gpsd)..."
    
    if ! command_exists gpsd; then
        print_warning "gpsd not installed, skipping GPS setup"
        return 1
    fi
    
    # Check if gpsd is running
    if systemctl is-active --quiet gpsd 2>/dev/null; then
        print_info "gpsd service is already running"
    else
        print_info "Starting gpsd service..."
        sudo systemctl start gpsd 2>/dev/null || {
            print_warning "Could not start gpsd service (may need manual configuration)"
        }
    fi
    
    # Enable gpsd on boot
    sudo systemctl enable gpsd 2>/dev/null || {
        print_warning "Could not enable gpsd on boot"
    }
    
    print_info "GPS setup complete. To use GPS, connect your USB GPS device and run:"
    print_info "  sudo gpsd /dev/ttyUSB0 -F /var/run/gpsd.sock"
    print_info "  Or configure /etc/default/gpsd with your device path"
    
    return 0
}

# Function to create config.ini if it doesn't exist
create_config() {
    print_status "Checking configuration file..."
    
    if [ ! -f "config.ini" ]; then
        print_info "Creating default config.ini..."
        cat > config.ini << 'EOF'
[DEFAULT]
# Monitor mode interface candidates (comma-separated)
# The tool will automatically detect and use these interfaces
monitor_candidates = wlan1,wlp0s20f0u2
EOF
        print_status "Created default config.ini"
    else
        print_info "config.ini already exists"
    fi
}

# Function to check WiFi interface
check_wifi_interface() {
    print_status "Checking for WiFi interfaces..."
    
    if command_exists iw; then
        INTERFACES=$(iw dev 2>/dev/null | grep -E "^Interface" | awk '{print $2}')
        if [ -z "$INTERFACES" ]; then
            print_warning "No wireless interfaces detected"
            print_info "Make sure your WiFi adapter is connected and drivers are installed"
        else
            print_info "Detected wireless interfaces:"
            for iface in $INTERFACES; do
                echo "  - $iface"
            done
        fi
    else
        print_warning "iw command not found, cannot check interfaces"
    fi
}

# Function to verify installation
verify_installation() {
    print_status "Verifying installation..."
    
    VERIFY_ERRORS=0
    
    # Check Python packages
    print_info "Checking Python packages..."
    python3 -c "import tabulate, serial, gps3, flask" 2>/dev/null || {
        print_error "Some Python packages are missing"
        ((VERIFY_ERRORS++))
    }
    
    # Check system commands
    print_info "Checking system commands..."
    COMMANDS=("aircrack-ng" "airodump-ng" "aireplay-ng" "john" "hashcat")
    for cmd in "${COMMANDS[@]}"; do
        if ! command_exists "$cmd"; then
            print_error "$cmd not found in PATH"
            ((VERIFY_ERRORS++))
        fi
    done
    
    # Check directories
    print_info "Checking directories..."
    DIRS=("logs" "collection" "archive" "tracking" "john" "hc")
    for dir in "${DIRS[@]}"; do
        if [ ! -d "$dir" ]; then
            print_error "Directory missing: $dir"
            ((VERIFY_ERRORS++))
        fi
    done
    
    if [ $VERIFY_ERRORS -eq 0 ]; then
        print_status "Installation verification passed!"
        return 0
    else
        print_error "Installation verification failed with $VERIFY_ERRORS errors"
        return 1
    fi
}

# Main execution
main() {
    echo "=========================================="
    echo "  MiFi Automated Setup Script"
    echo "=========================================="
    echo ""
    
    check_root
    
    print_status "Starting MiFi setup..."
    echo ""
    
    # Step 1: Create directories
    create_directories || print_error "Failed to create directories"
    echo ""
    
    # Step 2: Install system packages
    install_system_packages || print_error "Failed to install system packages"
    echo ""
    
    # Step 3: Install Python packages
    install_python_packages || print_error "Failed to install Python packages"
    echo ""
    
    # Step 4: Download rockyou.txt
    download_rockyou || print_warning "rockyou.txt not available (optional)"
    echo ""
    
    # Step 5: Setup GPS
    setup_gps || print_warning "GPS setup incomplete (optional)"
    echo ""
    
    # Step 6: Create config
    create_config
    echo ""
    
    # Step 7: Check WiFi interface
    check_wifi_interface
    echo ""
    
    # Step 8: Verify installation
    verify_installation
    echo ""
    
    # Summary
    echo "=========================================="
    echo "  Setup Summary"
    echo "=========================================="
    
    if [ $ERRORS -eq 0 ]; then
        print_status "Setup completed successfully!"
        echo ""
        print_info "Next steps:"
        echo "  1. Configure your WiFi interface (if needed):"
        echo "     sudo python3 mifi.py --mode config"
        echo ""
        echo "  2. Start collecting handshakes:"
        echo "     sudo python3 mifi.py --mode collect-manual"
        echo ""
        echo "  3. Or start the web dashboard:"
        echo "     python3 mifi.py --mode dashboard"
        echo ""
        echo "  4. View help for all options:"
        echo "     python3 mifi.py --help"
        echo ""
    else
        print_error "Setup completed with $ERRORS error(s) and $WARNINGS warning(s)"
        echo ""
        print_info "Please review the errors above and fix them manually"
        echo ""
        exit 1
    fi
    
    if [ $WARNINGS -gt 0 ]; then
        print_warning "There were $WARNINGS warning(s) - review them above"
    fi
}

# Run main function
main

