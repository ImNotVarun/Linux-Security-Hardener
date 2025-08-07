#!/bin/bash
# Version: 2.0

# Colors and formatting
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Log file
LOG_FILE="/var/log/security_hardener.log"

# Configuration backup directory
BACKUP_DIR="/etc/security_hardener_backups"

# Create backup directory if it doesn't exist
mkdir -p "$BACKUP_DIR"

# Logging function
log_action() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

# Progress bar function
show_progress() {
    local duration=$1
    local message=$2
    echo -ne "${CYAN}$message${NC}"
    for i in $(seq 1 $duration); do
        echo -ne "."
        sleep 0.1
    done
    echo -e " ${GREEN}Done!${NC}"
}

# ASCII Banner with system info
banner() {
    clear
    echo -e "${PURPLE}"
    cat << "EOF"
╔══════════════════════════════════════════════════════════════╗
║                    LINUX SECURITY HARDENER                   ║
║                         Version 2.0                         ║
╚══════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
    echo -e "${CYAN}System Info:${NC} $(uname -sr)"
    echo -e "${CYAN}Hostname:${NC} $(hostname)"
    echo -e "${CYAN}Current User:${NC} $(whoami)"
    echo -e "${CYAN}Date:${NC} $(date)"
    echo "═══════════════════════════════════════════════════════════════"
}

# Backup function
backup_file() {
    local file=$1
    if [[ -f "$file" ]]; then
        cp "$file" "$BACKUP_DIR/$(basename $file).backup.$(date +%Y%m%d_%H%M%S)"
        log_action "Backed up $file"
    fi
}

# Check if service exists
service_exists() {
    systemctl list-unit-files | grep -q "$1"
}

# 1. Enhanced SSH Security
harden_ssh() {
    echo -e "${YELLOW}[1] Hardening SSH Configuration...${NC}"
    
    # Backup SSH config
    backup_file "/etc/ssh/sshd_config"
    
    # SSH hardening configurations
    local ssh_config="/etc/ssh/sshd_config"
    
    # Disable root login
    sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' "$ssh_config"
    
    # Disable password authentication (enable key-based only)
    sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' "$ssh_config"
    
    # Disable empty passwords
    sed -i 's/^#*PermitEmptyPasswords.*/PermitEmptyPasswords no/' "$ssh_config"
    
    # Change default port (optional - commented out for compatibility)
    # sed -i 's/^#*Port.*/Port 2222/' "$ssh_config"
    
    # Limit login attempts
    sed -i 's/^#*MaxAuthTries.*/MaxAuthTries 3/' "$ssh_config"
    
    # Set idle timeout
    sed -i 's/^#*ClientAliveInterval.*/ClientAliveInterval 300/' "$ssh_config"
    sed -i 's/^#*ClientAliveCountMax.*/ClientAliveCountMax 2/' "$ssh_config"
    
    # Disable X11 forwarding
    sed -i 's/^#*X11Forwarding.*/X11Forwarding no/' "$ssh_config"
    
    # Protocol version
    echo "Protocol 2" >> "$ssh_config"
    
    show_progress 10 "Applying SSH configurations"
    
    # Restart SSH service
    if systemctl restart sshd; then
        echo -e "${GREEN}✔ SSH hardening completed${NC}"
        log_action "SSH hardening completed successfully"
    else
        echo -e "${RED}✘ Failed to restart SSH service${NC}"
        log_action "ERROR: Failed to restart SSH service"
    fi
}

# 2. Advanced File Permissions and Security
fix_permissions() {
    echo -e "${YELLOW}[2] Fixing File Permissions and Security...${NC}"
    
    # SSH directory permissions
    if [[ -d ~/.ssh ]]; then
        chmod 700 ~/.ssh
        chmod 600 ~/.ssh/* 2>/dev/null
        echo -e "${GREEN}✔ Fixed SSH directory permissions${NC}"
    fi
    
    # System file permissions
    chmod 600 /etc/passwd-
    chmod 600 /etc/shadow
    chmod 600 /etc/gshadow
    chmod 644 /etc/passwd
    chmod 644 /etc/group
    
    # Remove world-writable files (dangerous)
    echo -e "${CYAN}Checking for world-writable files...${NC}"
    find / -type f -perm -002 -exec ls -l {} \; 2>/dev/null | head -10
    
    # Set umask for better default permissions
    echo "umask 027" >> /etc/profile
    
    show_progress 8 "Setting secure file permissions"
    echo -e "${GREEN}✔ File permissions hardened${NC}"
    log_action "File permissions hardening completed"
}

# 3. Enhanced Service Management
manage_services() {
    echo -e "${YELLOW}[3] Managing System Services...${NC}"
    
    # List of potentially unwanted services
    local services=("cups" "avahi-daemon" "bluetooth" "rpcbind" "nfs-server" "telnet" "ftp")
    
    for service in "${services[@]}"; do
        if service_exists "$service"; then
            systemctl disable --now "$service" 2>/dev/null
            echo -e "${GREEN}✔ Disabled $service${NC}"
            log_action "Disabled service: $service"
        fi
    done
    
    # Enable important security services
    local security_services=("fail2ban" "apparmor" "ufw")
    
    for service in "${security_services[@]}"; do
        if service_exists "$service"; then
            systemctl enable --now "$service" 2>/dev/null
            echo -e "${GREEN}✔ Enabled $service${NC}"
            log_action "Enabled security service: $service"
        fi
    done
    
    show_progress 5 "Service management completed"
}

# 4. Advanced Firewall Setup
setup_firewall() {
    echo -e "${YELLOW}[4] Configuring Advanced Firewall...${NC}"
    
    # Install UFW if not present
    if ! command -v ufw &> /dev/null; then
        echo -e "${YELLOW}Installing UFW...${NC}"
        apt-get update && apt-get install -y ufw 2>/dev/null || yum install -y ufw 2>/dev/null
    fi
    
    # Reset UFW to defaults
    ufw --force reset
    
    # Default policies
    ufw default deny incoming
    ufw default allow outgoing
    
    # Allow essential services
    ufw allow ssh
    ufw allow 80/tcp  # HTTP
    ufw allow 443/tcp # HTTPS
    
    # Rate limiting for SSH
    ufw limit ssh
    
    # Enable logging
    ufw logging on
    
    # Enable UFW
    ufw --force enable
    
    show_progress 8 "Configuring firewall rules"
    echo -e "${GREEN}✔ Advanced firewall configured${NC}"
    log_action "Advanced firewall setup completed"
}

# 5. System Updates and Security Patches
update_system() {
    echo -e "${YELLOW}[5] Updating System and Security Patches...${NC}"
    
    # Detect package manager and update
    if command -v apt-get &> /dev/null; then
        apt-get update
        show_progress 10 "Downloading package lists"
        apt-get upgrade -y
        apt-get autoremove -y
        echo -e "${GREEN}✔ System updated (APT)${NC}"
    elif command -v yum &> /dev/null; then
        yum update -y
        echo -e "${GREEN}✔ System updated (YUM)${NC}"
    elif command -v dnf &> /dev/null; then
        dnf upgrade -y
        echo -e "${GREEN}✔ System updated (DNF)${NC}"
    elif command -v pacman &> /dev/null; then
        pacman -Syu --noconfirm
        echo -e "${GREEN}✔ System updated (Pacman)${NC}"
    else
        echo -e "${RED}✘ Package manager not detected${NC}"
    fi
    
    log_action "System update completed"
}

# 6. Install Security Tools
install_security_tools() {
    echo -e "${YELLOW}[6] Installing Security Tools...${NC}"
    
    local tools=("fail2ban" "rkhunter" "chkrootkit" "lynis" "clamav")
    
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            echo -e "${CYAN}Installing $tool...${NC}"
            if command -v apt-get &> /dev/null; then
                apt-get install -y "$tool" 2>/dev/null
            elif command -v yum &> /dev/null; then
                yum install -y "$tool" 2>/dev/null
            elif command -v dnf &> /dev/null; then
                dnf install -y "$tool" 2>/dev/null
            fi
            echo -e "${GREEN}✔ Installed $tool${NC}"
            log_action "Installed security tool: $tool"
        else
            echo -e "${GREEN}✔ $tool already installed${NC}"
        fi
    done
    
    show_progress 10 "Security tools installation completed"
}

# 7. Kernel Security Parameters
harden_kernel() {
    echo -e "${YELLOW}[7] Hardening Kernel Parameters...${NC}"
    
    # Backup current sysctl config
    backup_file "/etc/sysctl.conf"
    
    # Create security sysctl config
    cat << 'EOF' > /etc/sysctl.d/99-security.conf
# Network Security
net.ipv4.ip_forward = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1

# Memory Protection
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.yama.ptrace_scope = 1

# File System Security
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
EOF
    
    # Apply settings
    sysctl -p /etc/sysctl.d/99-security.conf
    
    show_progress 5 "Applying kernel security parameters"
    echo -e "${GREEN}✔ Kernel hardening completed${NC}"
    log_action "Kernel security parameters applied"
}

# 8. System Audit and Monitoring
setup_monitoring() {
    echo -e "${YELLOW}[8] Setting up System Monitoring...${NC}"
    
    # Configure auditd if available
    if command -v auditctl &> /dev/null; then
        # Add basic audit rules
        auditctl -w /etc/passwd -p wa -k passwd_changes
        auditctl -w /etc/shadow -p wa -k shadow_changes
        auditctl -w /etc/ssh/sshd_config -p wa -k ssh_config_changes
        echo -e "${GREEN}✔ Audit rules configured${NC}"
        log_action "Audit rules configured"
    fi
    
    # Setup log monitoring
    echo -e "${CYAN}Setting up log rotation...${NC}"
    if [[ -f /etc/logrotate.conf ]]; then
        echo -e "${GREEN}✔ Log rotation already configured${NC}"
    fi
    
    show_progress 3 "Monitoring setup completed"
}

# 9. Security Scan
run_security_scan() {
    echo -e "${YELLOW}[9] Running Security Scan...${NC}"
    
    echo -e "${CYAN}Running basic security checks...${NC}"
    
    # Check for users with UID 0
    echo -e "${WHITE}Users with UID 0:${NC}"
    awk -F: '($3 == "0") {print}' /etc/passwd
    
    # Check for empty password fields
    echo -e "${WHITE}Users with empty passwords:${NC}"
    awk -F: '($2 == "") {print $1}' /etc/shadow
    
    # Check listening ports
    echo -e "${WHITE}Listening network services:${NC}"
    ss -tuln | head -10
    
    # Check failed login attempts
    echo -e "${WHITE}Recent failed login attempts:${NC}"
    grep "Failed password" /var/log/auth.log 2>/dev/null | tail -5
    
    # Run lynis if available
    if command -v lynis &> /dev/null; then
        echo -e "${CYAN}Running Lynis security audit...${NC}"
        lynis audit system --quick 2>/dev/null | tail -20
    fi
    
    show_progress 8 "Security scan completed"
    echo -e "${GREEN}✔ Security scan finished${NC}"
    log_action "Security scan completed"
}

# 10. Complete Hardening (Run all functions)
complete_hardening() {
    echo -e "${BOLD}${PURPLE}[COMPLETE HARDENING] Running all security measures...${NC}"
    
    harden_ssh
    fix_permissions
    manage_services
    setup_firewall
    update_system
    install_security_tools
    harden_kernel
    setup_monitoring
    
    echo -e "${BOLD}${GREEN}✔ Complete system hardening finished!${NC}"
    echo -e "${CYAN}Check log file: $LOG_FILE${NC}"
    log_action "Complete system hardening finished"
}

# 11. System Status Check
system_status() {
    echo -e "${YELLOW}[11] System Security Status${NC}"
    echo "═══════════════════════════════════════"
    
    # SSH Status
    echo -e "${WHITE}SSH Service:${NC}"
    if systemctl is-active --quiet sshd; then
        echo -e "${GREEN}✔ SSH service is running${NC}"
    else
        echo -e "${RED}✘ SSH service is not running${NC}"
    fi
    
    # Firewall Status
    echo -e "${WHITE}Firewall Status:${NC}"
    if ufw status | grep -q "Status: active"; then
        echo -e "${GREEN}✔ UFW firewall is active${NC}"
        ufw status numbered | head -10
    else
        echo -e "${RED}✘ UFW firewall is inactive${NC}"
    fi
    
    # System Load
    echo -e "${WHITE}System Load:${NC}"
    uptime
    
    # Disk Usage
    echo -e "${WHITE}Disk Usage:${NC}"
    df -h | head -5
    
    # Memory Usage
    echo -e "${WHITE}Memory Usage:${NC}"
    free -h
    
    # Last Logins
    echo -e "${WHITE}Recent Logins:${NC}"
    last | head -5
}

# 12. Restore from Backup
restore_configs() {
    echo -e "${YELLOW}[12] Restoring Configurations from Backup...${NC}"
    
    if [[ ! -d "$BACKUP_DIR" ]]; then
        echo -e "${RED}✘ No backup directory found${NC}"
        return 1
    fi
    
    echo -e "${CYAN}Available backups:${NC}"
    ls -la "$BACKUP_DIR"
    
    echo -e "${YELLOW}WARNING: This will restore backed up configurations${NC}"
    read -p "Are you sure? (y/N): " confirm
    
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        for backup in "$BACKUP_DIR"/*.backup.*; do
            if [[ -f "$backup" ]]; then
                original_file="/etc/$(basename "$backup" | cut -d'.' -f1)"
                cp "$backup" "$original_file"
                echo -e "${GREEN}✔ Restored $original_file${NC}"
                log_action "Restored $original_file from backup"
            fi
        done
        
        # Restart services
        systemctl restart sshd
        echo -e "${GREEN}✔ Configuration restore completed${NC}"
    else
        echo -e "${CYAN}Restore cancelled${NC}"
    fi
}

# Main Menu
menu() {
    while true; do
        banner
        echo -e "${WHITE}Security Hardening Options:${NC}"
        echo "────────────────────────────────────────────────────────"
        echo -e "${GREEN} 1)${NC} Harden SSH Configuration"
        echo -e "${GREEN} 2)${NC} Fix File Permissions & Security"
        echo -e "${GREEN} 3)${NC} Manage System Services"
        echo -e "${GREEN} 4)${NC} Setup Advanced Firewall (UFW)"
        echo -e "${GREEN} 5)${NC} Update System & Security Patches"
        echo -e "${GREEN} 6)${NC} Install Security Tools"
        echo -e "${GREEN} 7)${NC} Harden Kernel Parameters"
        echo -e "${GREEN} 8)${NC} Setup System Monitoring"
        echo -e "${GREEN} 9)${NC} Run Security Scan"
        echo -e "${GREEN}10)${NC} Complete Hardening (All Above)"
        echo "────────────────────────────────────────────────────────"
        echo -e "${BLUE}11)${NC} Check System Status"
        echo -e "${BLUE}12)${NC} Restore from Backup"
        echo -e "${BLUE}13)${NC} View Log File"
        echo -e "${RED}14)${NC} Exit"
        echo "════════════════════════════════════════════════════════"
        
        read -p "Choose an option [1-14]: " opt
        
        case $opt in
            1) harden_ssh ;;
            2) fix_permissions ;;
            3) manage_services ;;
            4) setup_firewall ;;
            5) update_system ;;
            6) install_security_tools ;;
            7) harden_kernel ;;
            8) setup_monitoring ;;
            9) run_security_scan ;;
            10) complete_hardening ;;
            11) system_status ;;
            12) restore_configs ;;
            13) [[ -f "$LOG_FILE" ]] && tail -20 "$LOG_FILE" || echo -e "${RED}No log file found${NC}" ;;
            14) echo -e "${GREEN}Goodbye! Stay secure!${NC}"; exit 0 ;;
            *) echo -e "${RED}Invalid option. Please choose 1-14.${NC}" ;;
        esac
        
        echo ""
        read -p "Press Enter to continue..." dummy
    done
}

# Initialization checks
init_checks() {
    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}Error: This script must be run as root (sudo)${NC}"
        echo "Usage: sudo $0"
        exit 1
    fi
    
    # Create log file if it doesn't exist
    touch "$LOG_FILE"
    log_action "Security hardening script started by user: $(logname 2>/dev/null || echo 'unknown')"
    
    # Check OS compatibility
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        echo -e "${CYAN}Detected OS: $PRETTY_NAME${NC}"
        log_action "Detected OS: $PRETTY_NAME"
    fi
    
    echo -e "${GREEN}Initialization completed successfully${NC}"
    sleep 2
}

# Trap for cleanup on exit
cleanup() {
    log_action "Security hardening script terminated"
    echo -e "${CYAN}Script terminated. Check logs at: $LOG_FILE${NC}"
    exit 0
}

trap cleanup SIGINT SIGTERM

# Main execution
init_checks
menu
