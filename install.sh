#!/bin/bash

# Exit on error
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Print with color
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Detect OS and architecture
detect_platform() {
    local os=""
    local arch=""
    
    # Detect OS
    case "$(uname -s)" in
        Linux*)     os="linux";;
        Darwin*)    os="darwin";;
        *)          print_error "Unsupported operating system"; exit 1;;
    esac
    
    # Detect architecture
    case "$(uname -m)" in
        x86_64)     arch="x86_64";;
        aarch64)    arch="aarch64";;
        arm64)      arch="aarch64";;
        *)          print_error "Unsupported architecture"; exit 1;;
    esac
    
    # For Linux, detect if it's musl
    if [ "$os" = "linux" ]; then
        if ldd --version 2>&1 | grep -q musl; then
            os="linux-musl"
        fi
    fi
    
    echo "${os}-${arch}"
}

# Get latest release version
get_latest_version() {
    local repo="cyfrin/zksync-upgrade-verification-rs"
    curl -s "https://api.github.com/repos/${repo}/releases/latest" | grep -Po '"tag_name": "\K.*?(?=")'
}

# Download and install binary
install_binary() {
    local platform=$1
    local version=$2
    local repo="cyfrin/zksync-upgrade-verification-rs"
    local binary_name="zkgov-check"
    
    # Create temporary directory
    local tmp_dir=$(mktemp -d)
    cd "$tmp_dir"
    
    # Download the release
    print_status "Downloading version ${version} for ${platform}..."
    local url="https://github.com/${repo}/releases/download/${version}/${binary_name}-${platform}.tar.gz"
    
    if ! curl -L -o "${binary_name}.tar.gz" "$url"; then
        print_error "Failed to download binary"
        cd - > /dev/null
        rm -rf "$tmp_dir"
        exit 1
    fi
    
    # Extract the archive
    tar xzf "${binary_name}.tar.gz"
    
    # Determine installation directory
    local install_dir=""
    if [ "$(uname -s)" = "Darwin" ]; then
        install_dir="/usr/local/bin"
        if [ ! -d "$install_dir" ]; then
            install_dir="$HOME/.local/bin"
        fi
    else
        install_dir="$HOME/.local/bin"
    fi
    
    # Create installation directory if it doesn't exist
    mkdir -p "$install_dir"
    
    # Move binary to installation directory
    print_status "Installing binary to ${install_dir}..."
    mv "$binary_name" "$install_dir/"
    
    # Make binary executable
    chmod +x "$install_dir/$binary_name"
    
    # Clean up
    cd - > /dev/null
    rm -rf "$tmp_dir"
    
    # Add to PATH if not already there
    if [[ ":$PATH:" != *":$install_dir:"* ]]; then
        local shell_rc=""
        case "$SHELL" in
            */zsh)  shell_rc="$HOME/.zshrc";;
            */bash) shell_rc="$HOME/.bashrc";;
            *)      shell_rc="$HOME/.profile";;
        esac
        
        if [ -f "$shell_rc" ]; then
            echo "export PATH=\"\$PATH:$install_dir\"" >> "$shell_rc"
            print_warning "Added ${install_dir} to PATH in ${shell_rc}"
            print_warning "Please run 'source ${shell_rc}' or restart your shell to apply changes"
        fi
    fi
    
    print_status "Installation complete! You can now use '${binary_name}' from anywhere."
}

# Main installation process
main() {
    print_status "Detecting platform..."
    local platform=$(detect_platform)
    print_status "Detected platform: ${platform}"
    
    print_status "Fetching latest version..."
    local version=$(get_latest_version)
    if [ -z "$version" ]; then
        print_error "Failed to get latest version"
        exit 1
    fi
    print_status "Latest version: ${version}"
    
    install_binary "$platform" "$version"
}

# Run main function
main 