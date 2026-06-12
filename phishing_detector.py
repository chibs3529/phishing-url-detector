import re
import urllib.parse
from datetime import datetime


REPORT_FILE = "scan_results.txt"

# known URL shorteners often used to hide phishing destinations
URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at", "is.gd"
]

# legitimate brands that phishers commonly impersonate
TARGETED_BRANDS = [
    "paypal", "apple", "google", "microsoft", "amazon", "netflix",
    "facebook", "instagram", "bank", "chase", "wellsfargo", "hsbc",
    "dhl", "fedex", "ups", "dropbox", "linkedin", "twitter"
]

# words that show up a lot in phishing URLs
PHISHING_KEYWORDS = [
    "secure", "verify", "update", "confirm", "login", "signin",
    "account", "billing", "suspended", "unusual", "alert",
    "click", "free", "winner", "prize", "urgent", "limited"
]

# legitimate TLDs are fine, these less common ones get flagged
SUSPICIOUS_TLDS = [
    ".xyz", ".top", ".club", ".online", ".site", ".info",
    ".tk", ".ml", ".ga", ".cf", ".gq", ".pw", ".cc"
]


def extract_parts(url):
    # make sure the URL has a scheme so urlparse works properly
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urllib.parse.urlparse(url)
    domain = parsed.netloc.lower()

    # strip www.
    if domain.startswith("www."):
        domain = domain[4:]

    return {
        "url":      url,
        "scheme":   parsed.scheme,
        "domain":   domain,
        "path":     parsed.path,
        "query":    parsed.query,
        "full":     parsed.netloc + parsed.path + ("?" + parsed.query if parsed.query else "")
    }


def check_https(parts):
    if parts["scheme"] != "https":
        return "Uses HTTP instead of HTTPS — connection is not encrypted"
    return None


def check_ip_address(parts):
    # phishing URLs sometimes use raw IP addresses instead of domain names
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}', parts["domain"]):
        return f"Domain is an IP address ({parts['domain']}) — legitimate sites rarely do this"
    return None


def check_url_shortener(parts):
    for shortener in URL_SHORTENERS:
        if parts["domain"] == shortener or parts["domain"].endswith("." + shortener):
            return f"URL shortener detected ({shortener}) — may be hiding the real destination"
    return None


def check_brand_impersonation(parts):
    full = parts["full"].lower()
    hits = []
    for brand in TARGETED_BRANDS:
        if brand in full:
            # if the brand name is in the URL but the domain isn't actually that brand
            # e.g. paypal-secure.com or apple-id-verify.com
            if brand not in parts["domain"].split(".")[0]:
                hits.append(brand)
    if hits:
        return f"Possible brand impersonation: {', '.join(hits)}"
    return None


def check_suspicious_keywords(parts):
    full = (parts["path"] + parts["query"]).lower()
    found = [kw for kw in PHISHING_KEYWORDS if kw in full]
    if len(found) >= 2:
        return f"Multiple phishing keywords in URL: {', '.join(found)}"
    return None


def check_tld(parts):
    for tld in SUSPICIOUS_TLDS:
        if parts["domain"].endswith(tld):
            return f"Suspicious TLD detected: {tld}"
    return None


def check_subdomain_depth(parts):
    # lots of subdomains is a common trick e.g. paypal.secure.login.attacker.com
    parts_list = parts["domain"].split(".")
    if len(parts_list) > 4:
        return f"Excessive subdomains ({len(parts_list) - 2}) — may be trying to look like a trusted domain"
    return None


def check_special_chars(parts):
    # hyphens in domain names are sometimes used to mimic real domains
    domain = parts["domain"]
    hyphen_count = domain.count("-")
    if hyphen_count >= 3:
        return f"Many hyphens in domain ({hyphen_count}) — e.g. paypal-secure-login-verify.com"
    return None


def check_url_length(parts):
    if len(parts["url"]) > 100:
        return f"URL is very long ({len(parts['url'])} chars) — long URLs can hide the real destination"
    return None


def check_at_symbol(parts):
    # the @ symbol in a URL means the browser ignores everything before it
    # attackers use this: http://legitimate.com@evil.com
    if "@" in parts["domain"] or "@" in parts["path"]:
        return "@ symbol in URL — browser will ignore everything before it, real destination may differ"
    return None


def analyse_url(url):
    parts = extract_parts(url)

    checks = [
        check_https,
        check_ip_address,
        check_url_shortener,
        check_brand_impersonation,
        check_suspicious_keywords,
        check_tld,
        check_subdomain_depth,
        check_special_chars,
        check_url_length,
        check_at_symbol,
    ]

    warnings = []
    for check in checks:
        result = check(parts)
        if result:
            warnings.append(result)

    # risk level based on number of warnings
    if len(warnings) == 0:
        risk = "Low"
    elif len(warnings) <= 2:
        risk = "Medium"
    elif len(warnings) <= 4:
        risk = "High"
    else:
        risk = "Critical"

    return parts, warnings, risk


def display_result(url, parts, warnings, risk):
    risk_labels = {
        "Low":      "Low      — looks clean",
        "Medium":   "Medium   — worth checking",
        "High":     "High     — likely suspicious",
        "Critical": "Critical — probable phishing"
    }

    print(f"\nURL       : {url}")
    print(f"Domain    : {parts['domain']}")
    print(f"Risk      : {risk_labels[risk]}")
    print(f"Warnings  : {len(warnings)}")

    if warnings:
        print("\nIssues found:")
        for w in warnings:
            print(f"  - {w}")
    else:
        print("\nNo issues detected.")


def save_result(url, parts, warnings, risk):
    with open(REPORT_FILE, "a", encoding="utf-8") as f:
        f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}]\n")
        f.write(f"URL    : {url}\n")
        f.write(f"Domain : {parts['domain']}\n")
        f.write(f"Risk   : {risk}\n")
        if warnings:
            for w in warnings:
                f.write(f"  - {w}\n")
        else:
            f.write("  No issues found\n")
        f.write("\n")


def run_demo():
    # a few test URLs to show what the tool catches
    test_urls = [
        "https://www.google.com/search?q=python",
        "http://paypal-secure-verify-login.com/account/update",
        "https://192.168.1.1/admin/login",
        "http://bit.ly/3xR9abc",
        "https://apple-id-verify.suspicious.xyz/signin?redirect=account",
        "https://www.microsoft.com/en-us/windows",
    ]

    print("\nRunning demo scan on sample URLs...\n")
    print("-" * 50)

    for url in test_urls:
        parts, warnings, risk = analyse_url(url)
        display_result(url, parts, warnings, risk)
        save_result(url, parts, warnings, risk)
        print("-" * 50)


def main():
    print("Phishing URL Detector")
    print("---------------------")
    print("\n1 - Check a single URL")
    print("2 - Run demo on sample URLs")

    choice = input("\nChoice: ").strip()

    if choice == "1":
        url = input("Enter URL to check: ").strip()
        if not url:
            print("No URL entered.")
            return
        parts, warnings, risk = analyse_url(url)
        display_result(url, parts, warnings, risk)
        save_result(url, parts, warnings, risk)
        print(f"\nResult saved to {REPORT_FILE}")

    elif choice == "2":
        run_demo()
        print(f"\nResults saved to {REPORT_FILE}")

    else:
        print("Invalid choice.")


if __name__ == "__main__":
    main()
