"""Textbook test payloads. Plain strings only: nothing here is executed or a working exploit."""

SQLI = [
    "' OR '1'='1",
    "' OR 1=1--",
    "admin'--",
    "1 UNION SELECT NULL,NULL,NULL--",
    "1; DROP TABLE users--",
    "' AND SLEEP(5)--",
    "1' ORDER BY 10--",
]
XSS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    '"><script>alert(document.domain)</script>',
    "javascript:alert(1)",
]
PATH_TRAVERSAL = [
    "../../../../etc/passwd",
    "..%2f..%2f..%2fwindows/win.ini",
    "....//....//etc/shadow",
    "%2e%2e/%2e%2e/etc/hosts",
]
SCANNER_UAS = [
    "sqlmap/1.7.2#stable (https://sqlmap.org)",
    "Mozilla/5.00 (Nikto/2.1.5) (Evasions:None) (Test:Port Check)",
    "Nmap Scripting Engine; https://nmap.org/book/nse.html",
    "Mozilla/4.0 (Hydra)",
    "OWASP-ZAP/2.15",
]
PROBE_PATHS = [
    "/admin",
    "/.git/config",
    "/backup.zip",
    "/wp-login.php",
    "/phpmyadmin",
    "/.env",
    "/server-status",
    "/robots.txt",
    "/api/v1/users",
    "/console",
]
BENIGN_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
    "Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0",
]
BENIGN_PATHS = [
    "/",
    "/products",
    "/products/1042",
    "/products/2210",
    "/search?q=headphones",
    "/search?q=running+shoes",
    "/cart",
    "/checkout",
    "/account/orders",
    "/static/app.js",
]
# base64 of the harmless text "Get-Date": shaped like an encoded PowerShell launch, nothing more
ENCODED_PS = "RwBlAHQALQBEAGEAdABlAA=="
