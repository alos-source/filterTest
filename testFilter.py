import socket
import platform
import os
import re
try:
    import requests
except ImportError:
    print("WARNUNG: Das Modul 'requests' wird für die HTTP(S)-Prüfung (z.B. CUII-Weiterleitungen) benötigt.")
    print("Bitte installieren Sie es mit: pip install requests")
    print("Die HTTP(S)-Prüfungen auf Weiterleitungen werden übersprungen.")
    requests = None

# Liste von Domains, die HÄUFIG durch Adblocker/DNS-Filter gesperrt werden
# oder die man bewusst für Tests nutzen könnte.
# Dies sind KEINE CUII-Domains, sondern typische Werbe-/Tracking-Domains.
TEST_DOMAINS = [
    "doubleclick.net",
    "tracking.google.com",
    "ads.youtube.com",
    "ad.atdmt.com",
    "google-analytics.com",
    "analytics.facebook.com",
    "bad.domain.example.com", # Ein fiktiver Domain-Name, der bei DNS-Sperren oft auf 0.0.0.0 umgeleitet wird
    "canna-power.to", # Beispiel für eine Domain, die oft in CUII-Kontexten verwendet wird
    "serienjunkies.org", # Beispiel für eine Domain, die oft in CUII-Kontexten verwendet wird
    "streamcloud.eu", # Beispiel für eine Domain, die oft in CUII-Kontexten verwendet wird
    "ww4.kinox.to", # Beispiel für eine Domain, die oft in CUII-Kontexten verwendet wird
    "sci-hub.se", # Beispiel für eine Domain, die oft in CUII-Kontexten verwendet wird
    "rtde.me", # Beispiel für eine Domain, die oft in Politischen-Kontexten verwendet wird
]

# Status-Konstanten für DNS-Auflösung
DNS_STATUS_RESOLVED = "RESOLVED_OK"
DNS_STATUS_BLOCKED_NULL = "BLOCKED_POINTS_TO_0.0.0.0"
DNS_STATUS_BLOCKED_LOCALHOST = "BLOCKED_POINTS_TO_127.0.0.1"
DNS_STATUS_FAILED_RESOLUTION = "FAILED_TO_RESOLVE"
HTTP_STATUS_REDIRECTED_CUII = "REDIRECTED_TO_CUII_NOTICE"
DNS_STATUS_ERROR = "RESOLUTION_ERROR"
HTTP_REQUEST_ERROR = "HTTP_REQUEST_ERROR"


def check_domain_accessibility(domain):
    """
    Versucht, eine Domain aufzulösen (DNS) und prüft dann auf HTTP(S)-Ebene
    auf bekannte Weiterleitungen (z.B. CUII).
    Gibt einen Status sowie Details (IPs, URL oder Fehlermeldung) zurück.
    """
    try:
        _hostname, _aliaslist, ip_addresses = socket.gethostbyname_ex(domain)
        ip_addresses = [ip for ip in ip_addresses if ip] # Filtere leere Einträge

        if not ip_addresses:
            return DNS_STATUS_FAILED_RESOLUTION, "No IP addresses returned (DNS)"

        resolved_ips_set = set(ip_addresses)
        ip_list_str = ", ".join(sorted(list(resolved_ips_set)))

        if '0.0.0.0' in resolved_ips_set:
            return DNS_STATUS_BLOCKED_NULL, f"Points to {ip_list_str}"
        if '127.0.0.1' in resolved_ips_set:
            return DNS_STATUS_BLOCKED_LOCALHOST, f"Points to {ip_list_str}"

        # Wenn DNS okay ist und 'requests' verfügbar ist, prüfe auf HTTP(S)-Weiterleitungen
        if requests:
            urls_to_check = [f"http://{domain}", f"https://{domain}"]
            for url_to_check in urls_to_check:
                try:
                    response = requests.get(
                        url_to_check,
                        allow_redirects=False, # Wichtig, um den Redirect selbst zu sehen
                        timeout=5,
                        headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
                    )
                    if response.status_code in [301, 302, 303, 307, 308]: # HTTP Redirect Status Codes
                        location = response.headers.get('Location', '')
                        if 'notice.cuii.info' in location.lower():
                            return HTTP_STATUS_REDIRECTED_CUII, f"Redirects from {url_to_check} to {location}"
                except requests.exceptions.Timeout:
                    # Gebe einen spezifischen Fehler zurück, wenn ein Timeout auftritt,
                    # aber fahre nicht mit der nächsten URL fort, da dies ein Problem mit der Domain sein könnte.
                    return HTTP_REQUEST_ERROR, f"Timeout bei Zugriff auf {url_to_check}"
                except requests.exceptions.RequestException:
                    # Andere HTTP-Fehler (z.B. ConnectionError, SSL-Probleme)
                    # Diese deuten nicht direkt auf eine CUII-Sperre hin.
                    # Wenn ein HTTP-Fehler auftritt, aber keine CUII-Umleitung, gilt DNS als primär.
                    pass # Versuche die nächste URL (http/https) oder falle durch zu DNS_STATUS_RESOLVED
        
        # Wenn DNS okay war und keine CUII-Weiterleitung gefunden wurde (oder requests nicht verfügbar)
        return DNS_STATUS_RESOLVED, ip_list_str
    except socket.gaierror:
        return DNS_STATUS_FAILED_RESOLUTION, "Domain not found or DNS server issue (NXDOMAIN)"
    except Exception as e:
        return DNS_STATUS_ERROR, f"General Error: {e}"

def check_hosts_file():
    """
    Liest die Hosts-Datei und prüft, ob bekannte Blacklist-Einträge vorhanden sind.
    """
    hosts_path = ""
    if platform.system() == "Windows":
        hosts_path = os.path.join(os.environ["SystemRoot"], "System32", "drivers", "etc", "hosts")
    else: # Linux, macOS
        hosts_path = "/etc/hosts"

    if not os.path.exists(hosts_path):
        print(f"Warnung: Hosts-Datei nicht gefunden unter {hosts_path}")
        return []

    blocked_domains = []
    try:
        with open(hosts_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                match = re.match(r'^(127\.0\.0\.1|0\.0\.0\.0)\s+([^\s#]+)', line)
                if match:
                    domain = match.group(2)
                    # Eine einfache Heuristik: Ist es eine bekannte Werbe-/Tracking-Domain?
                    # Man könnte hier eine Liste von typischen Hosts-Blacklist-Einträgen pflegen.
                    if any(test_domain in domain for test_domain in TEST_DOMAINS): # Rudimentärer Check
                        blocked_domains.append(domain)
                    # Oder einfach alle geblockten Domains anzeigen
                    # blocked_domains.append(domain)
    except Exception as e:
        print(f"Fehler beim Lesen der Hosts-Datei: {e}")
    return blocked_domains

def get_dns_servers():
    """
    Versucht, die konfigurierten DNS-Server zu ermitteln.
    Dies ist betriebssystemabhängig und nicht immer zuverlässig von Python aus.
    Für Linux/macOS wird /etc/resolv.conf gelesen. Für Windows ist es komplexer.
    """
    dns_servers = []
    if platform.system() == "Linux" or platform.system() == "Darwin": # macOS
        try:
            with open("/etc/resolv.conf", 'r') as f:
                for line in f:
                    if line.startswith('nameserver'):
                        parts = line.split()
                        if len(parts) > 1:
                            dns_servers.append(parts[1])
        except FileNotFoundError:
            pass # resolv.conf might not exist or be empty
    elif platform.system() == "Windows":
        # Unter Windows ist das komplexer und erfordert oft externe Befehle oder WMI
        # Hier ein einfacher Versuch über ipconfig
        try:
            import subprocess
            result = subprocess.run(['ipconfig', '/all'], capture_output=True, text=True, encoding='cp850', errors='ignore')
            for line in result.stdout.splitlines():
                if "DNS-Server" in line or "DNS Servers" in line:
                    match = re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', line)
                    if match:
                        dns_servers.append(match.group(0))
        except Exception:
            pass # ipconfig might not be available or command failed
    return list(set(dns_servers)) # Eindeutige Liste

def main():
    print("--- Prüfung von Internet-Sperrlisten-Indikatoren ---")

    # 1. Hosts-Datei prüfen
    print("\n[1] Hosts-Datei Prüfung:")
    hosts_blocked_domains = check_hosts_file()
    if hosts_blocked_domains:
        print(f"  Potenziell geblockte Domains in der Hosts-Datei gefunden ({len(hosts_blocked_domains)}):")
        for domain in hosts_blocked_domains[:10]: # Zeige nur die ersten 10
            print(f"    - {domain}")
        if len(hosts_blocked_domains) > 10:
            print(f"    ... und {len(hosts_blocked_domains) - 10} weitere.")
        print("  Dies deutet auf eine aktive Hosts-Datei-basierte Sperrliste hin.")
    else:
        print("  Keine bekannten geblockten Einträge in der Hosts-Datei gefunden.")

    # 2. DNS-Server prüfen
    print("\n[2] Konfigurierte DNS-Server:")
    configured_dns = get_dns_servers()
    if configured_dns:
        print(f"  Ihre konfigurierten DNS-Server: {', '.join(configured_dns)}")
        if any(re.match(r'^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)', ip) for ip in configured_dns):
            print("  Hinweis: Ein oder mehrere DNS-Server sind private IP-Adressen (z.B. 192.168.x.x).")
            print("  Dies könnte auf ein lokales Pi-hole, AdGuard Home oder einen Router-internen DNS hindeuten.")
        elif any(ip in ["94.140.14.140", "94.140.14.141", "176.103.130.130", "176.103.130.131"] for ip in configured_dns):
            print("  Hinweis: AdGuard DNS-Server gefunden. AdGuard DNS filtert Werbung und Tracker.")
        elif any(ip in ["8.8.8.8", "8.8.4.4"] for ip in configured_dns):
            print("  Hinweis: Google Public DNS gefunden.")
        elif any(ip in ["1.1.1.1", "1.0.0.1"] for ip in configured_dns):
            print("  Hinweis: Cloudflare DNS gefunden.")
    else:
        print("  Konnte keine DNS-Server ermitteln (oder Standard-Provider-DNS).")

    # 3. DNS-Auflösung von Test-Domains
    print("\n[3] DNS-Auflösung und HTTP(S)-Erreichbarkeit von Test-Domains:")
    dns_level_block_count = 0
    cuii_redirect_count = 0
    http_error_count = 0
    resolution_summary = {}

    for domain in TEST_DOMAINS:
        status, detail = check_domain_accessibility(domain) # Geänderter Funktionsaufruf
        print(f"  {domain.ljust(30)}: {status} - {detail}")
        resolution_summary[status] = resolution_summary.get(status, 0) + 1
        
        if status in [DNS_STATUS_BLOCKED_NULL, DNS_STATUS_BLOCKED_LOCALHOST, DNS_STATUS_FAILED_RESOLUTION]:
            dns_level_block_count += 1
        elif status == HTTP_STATUS_REDIRECTED_CUII:
            cuii_redirect_count += 1
        elif status == HTTP_REQUEST_ERROR:
            http_error_count += 1

    print("\n  Zusammenfassung der Domain-Prüfungen:")
    # Definierte Reihenfolge für die Zusammenfassung
    status_order = [DNS_STATUS_RESOLVED, HTTP_STATUS_REDIRECTED_CUII, DNS_STATUS_BLOCKED_NULL, DNS_STATUS_BLOCKED_LOCALHOST, DNS_STATUS_FAILED_RESOLUTION, HTTP_REQUEST_ERROR, DNS_STATUS_ERROR]
    for status_key in status_order:
        if status_key in resolution_summary:
            count = resolution_summary[status_key]
            print(f"    - {status_key}: {count} Domain(s)")

    total_problematic_domains = dns_level_block_count + cuii_redirect_count # HTTP_REQUEST_ERROR nicht als "Sperre" zählen

    if total_problematic_domains > 0:
        print(f"\n  Insgesamt wurden {total_problematic_domains} von {len(TEST_DOMAINS)} Test-Domains als potenziell durch DNS-Manipulation geblockt oder auf eine CUII-Hinweisseite umgeleitet eingestuft.")
        if cuii_redirect_count > 0:
            print(f"  -> {cuii_redirect_count} Domain(s) wurde(n) auf eine CUII-Hinweisseite umgeleitet (z.B. notice.cuii.info).")
            print("     Dies ist ein starker Indikator für eine aktive CUII-Sperre durch den Internetanbieter.")
        if dns_level_block_count > 0:
            print(f"  -> {dns_level_block_count} Domain(s) zeigten Anzeichen klassischer DNS-Blockaden:")
        if resolution_summary.get(DNS_STATUS_BLOCKED_NULL, 0) > 0 or resolution_summary.get(DNS_STATUS_BLOCKED_LOCALHOST, 0) > 0 :
            print("  Mindestens eine Domain wurde auf eine typische Block-IP (z.B. 0.0.0.0, 127.0.0.1) umgeleitet.")
            print("     Dies deutet auf eine lokale (z.B. Hosts-Datei, Pi-hole) oder DNS-Provider-Sperre hin.")
        if resolution_summary.get(DNS_STATUS_FAILED_RESOLUTION, 0) > 0:
            print("  Mindestens eine Domain konnte nicht aufgelöst werden (z.B. NXDOMAIN, DNS-Serverproblem).")
            print("     Dies kann auf eine DNS-Sperre oder allgemeine DNS-Probleme hindeuten.")
    else:
        print("\n  Alle Test-Domains konnten erfolgreich aufgelöst und keiner typischen Block-IP oder CUII-Hinweisseite zugeordnet werden.")
        print("  Dies deutet darauf hin, dass keine der getesteten allgemeinen DNS-basierten Sperrlisten oder CUII-Sperren aktiv ist.")
    if http_error_count > 0 and requests is None:
        print(f"\n  Hinweis: {http_error_count} Domain(s) konnten nicht per HTTP(S) geprüft werden, da das 'requests'-Modul fehlt.")
    elif http_error_count > 0:
        print(f"\n  Hinweis: Bei {http_error_count} Domain(s) gab es Fehler bei der HTTP(S)-Anfrage (z.B. Timeout). Diese Seiten könnten offline sein oder andere Netzwerkprobleme haben.")

    print("\n--- Ende der Prüfung ---")
    print("Beachten Sie: Dieses Programm kann nicht alle Arten von Sperrlisten erkennen (z.B. Browser-Erweiterungen).")

if __name__ == "__main__":
    main()