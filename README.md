# phishing-url-detector

A Python tool that analyses URLs and flags characteristics commonly associated with phishing attacks. It checks for things like brand impersonation, suspicious TLDs, URL shorteners, raw IP addresses, and patterns that attackers use to make fake URLs look legitimate.

I built this while studying common phishing techniques and wanted to put the detection logic into something practical.

## How to run

No external libraries needed.

```
python phishing_detector.py
```

Choose option 1 to check a specific URL, or option 2 to run a demo scan against a set of sample URLs — including both clean and suspicious ones so you can see what the output looks like.

## What it checks

- HTTP vs HTTPS
- Raw IP address used as domain
- URL shortener services (bit.ly, tinyurl, etc.)
- Brand impersonation (PayPal, Apple, Microsoft, banks, etc.)
- Phishing keywords in the path or query string
- Suspicious TLDs (.xyz, .tk, .top, etc.)
- Excessive subdomains
- Unusual number of hyphens in domain name
- URL length
- @ symbol abuse

Each URL gets a risk rating: Low, Medium, High, or Critical based on how many issues are found.

## Output

Results print to the terminal and are appended to `scan_results.txt` with a timestamp.

## Limitations

This is pattern-based detection — it flags suspicious characteristics but isn't a definitive verdict. A URL scoring Low could still be malicious, and some legitimate URLs might trigger a warning. Always verify with additional tools for anything important.

## Author

Onah Joshua — [GitHub](https://github.com/chibs3529)
