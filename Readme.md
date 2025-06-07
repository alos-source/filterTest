# Internet Filter/Blocklist Indicator Script

This Python script helps to identify potential internet filtering or blocklisting mechanisms active on your system or network. It checks for common indicators such as:

1.  **Hosts File Modifications:** Scans your system's `hosts` file for entries that redirect domains to `0.0.0.0` or `127.0.0.1`.
2.  **Configured DNS Servers:** Attempts to identify your currently configured DNS servers and provides hints if known public DNS services (like Google, Cloudflare, AdGuard DNS) or private IP addresses (which might indicate a local resolver like Pi-hole or AdGuard Home) are in use.
3.  **DNS Resolution and HTTP(S) Accessibility of Test Domains:**
    *   It resolves a predefined list of test domains (typically ad/tracker domains or domains known to be affected by certain blocks).
    *   Checks if DNS resolution points to common block IPs (`0.0.0.0`, `127.0.0.1`).
    *   If DNS resolution is normal, it attempts to access the domain via HTTP and HTTPS.
    *   Specifically checks if a domain redirects to `notice.cuii.info`, which is a strong indicator of an ISP-level block by CUII (Clearingstelle Urheberrechtsverletzungen im Internet) in Germany.
    *   Reports DNS resolution failures or HTTP request errors.
4.  **Summary of Findings:** Provides a consolidated report of the checks.

## Prerequisites

*   Python 3.x
*   The `requests` library (for HTTP(S) checks, including CUII redirect detection):
    ```bash
    pip install requests
    ```
    If `requests` is not installed, the script will still run DNS checks but will skip HTTP(S) accessibility tests and CUII redirect detection.

## How to Use

1.  Save the script as `testFilter.py` (or any other `.py` name).
2.  Make sure you have Python installed and the `requests` library if you want full functionality.
3.  Run the script from your terminal:
    ```bash
    python testFilter.py
    ```

## Understanding the Output

The script will print information in several sections:

*   **[1] Hosts File Check:**
    *   Lists any domains found in your hosts file that are redirected to `0.0.0.0` or `127.0.0.1`.
*   **[2] Configured DNS Servers:**
    *   Shows the DNS servers it could detect.
    *   Provides hints based on the IP addresses (e.g., private IP, known public DNS).
*   **[3] DNS Resolution and HTTP(S) Accessibility of Test Domains:**
    *   For each domain in `TEST_DOMAINS`, it shows:
        *   `RESOLVED_OK`: Domain resolved to a regular IP address, and no CUII redirect was detected.
        *   `BLOCKED_POINTS_TO_0.0.0.0` / `BLOCKED_POINTS_TO_127.0.0.1`: Domain resolves to a block IP (likely DNS-level block).
        *   `FAILED_TO_RESOLVE`: DNS resolution failed (e.g., NXDOMAIN, server issue).
        *   `REDIRECTED_TO_CUII_NOTICE`: Domain successfully resolved, but an HTTP(S) request resulted in a redirect to `notice.cuii.info`.
        *   `HTTP_REQUEST_ERROR`: DNS resolved, but an error occurred during the HTTP(S) request (e.g., timeout).
        *   `RESOLUTION_ERROR`: A general error occurred during the check.
    *   A summary table shows how many domains fall into each status category.
    *   An overall assessment is provided based on the findings.

Entries of the cuii list might result either in REDIRECTED_TO_CUII_NOTICE or NXDOMAIN. For NXDOMAIN-Entries, online URL-Scanners like [URLScan.io](https://urlscan.io/) might help verifying if the site is actually available.

## Customization

You can modify the `TEST_DOMAINS` list within the script to include other domains you wish to test.

## Limitations

*   **Not Exhaustive:** This script checks for common indicators but cannot detect all possible filtering methods (e.g., deep packet inspection, browser extensions, some VPN-internal blocks).
*   **DNS Server Detection:** Reliably detecting all configured DNS servers across all operating systems from within Python can be challenging. The script uses common methods but might not always be 100% accurate, especially on Windows for complex network configurations.
*   **`requests` Dependency:** Full HTTP(S) checking, including CUII redirect detection, requires the `requests` library.
*   **Interpretation:** The results are indicators. A "blocked" status for a tracking domain might be intentional (e.g., due to an ad blocker). A CUII redirect is a strong sign of an ISP block.
* Might differ from your **Browser Experience:** Even here a domain is flagged as unavailable, it might be accessiable in your browser or vice versa. Your browsers might use different DNS settings, then tested here.

## CUII

The entries of the CUII blocking are listed at the inofficial cuiilist: https://cuiiliste.de/.

## References
- https://www.heise.de/news/Erste-Websperren-seit-Jahren-6020210.html
- https://netzpolitik.org/2025/netzsperren-provider-verstecken-welche-domains-sie-sperren/

## Disclaimer

This script is for informational and educational purposes. Use it responsibly. 

Please be also aware, that your scans might be logged on your local dns chain e.g. a router or adguard-dns server.