"""
Phishing URL Feature Extractor
Extracts lexical, structural, and keyword-based numerical features from raw URLs.
"""

import re
import tldextract

FEATURE_NAMES = [
    'url_length',
    'dot_count',
    'hyphen_count',
    'at_symbol',
    'double_slash_redirect',
    'has_ip_address',
    'subdomain_count',
    'domain_length',
    'https_flag',
    'suspicious_words'
]

SUSPICIOUS_KEYWORDS = [
    'login', 'verify', 'update', 'secure', 'bank', 
    'account', 'banking', 'confirm', 'signin', 'password',
    'credential', 'wallet', 'service', 'admin', 'auth'
]

IP_REGEX = re.compile(
    r'^(?:http[s]?://)?(?:www\.)?'
    r'(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
    r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'
    r'(?::\d+)?(?:/.*)?$',
    re.IGNORECASE
)

# Alternative IP host extraction pattern
RAW_IP_PATTERN = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
)


def extract_features(url: str) -> dict:
    """
    Extracts a dictionary of numerical cybersecurity features from a given URL string.
    
    Returns:
        dict: Feature name mapping to numerical values (float/int).
    """
    if not isinstance(url, str):
        url = str(url or '')

    url = url.strip()
    url_lower = url.lower()

    # 1. url_length: Total length of the URL
    url_length = len(url)

    # 2. dot_count: Number of '.' characters
    dot_count = url.count('.')

    # 3. hyphen_count: Number of '-' characters
    hyphen_count = url.count('-')

    # 4. at_symbol: Number of '@' characters
    at_symbol = url.count('@')

    # 5. double_slash_redirect: 1 if '//' appears in path (after initial http:// or https://), else 0
    after_scheme = re.sub(r'^https?://', '', url, flags=re.IGNORECASE)
    double_slash_redirect = 1 if '//' in after_scheme else 0

    # 6. has_ip_address: 1 if the domain is a raw IP address, else 0
    extracted = tldextract.extract(url)
    domain_candidate = extracted.domain
    subdomain_candidate = extracted.subdomain
    full_host = f"{subdomain_candidate}.{domain_candidate}.{extracted.suffix}".strip('.')
    
    # Check if host or url matches an IPv4 format
    has_ip = 1 if (IP_REGEX.match(url) or RAW_IP_PATTERN.search(full_host) or RAW_IP_PATTERN.match(domain_candidate)) else 0

    # 7. subdomain_count: Number of subdomains (using tldextract)
    if extracted.subdomain:
        subdomain_parts = [part for part in extracted.subdomain.split('.') if part]
        subdomain_count = len(subdomain_parts)
    else:
        subdomain_count = 0

    # 8. domain_length: Length of extracted domain name
    domain_length = len(extracted.domain) if extracted.domain else 0

    # 9. https_flag: 1 if URL starts with 'https', else 0
    https_flag = 1 if url_lower.startswith('https') else 0

    # 10. suspicious_words: 1 if suspicious keywords are in the URL, else 0
    suspicious_words = 1 if any(word in url_lower for word in SUSPICIOUS_KEYWORDS) else 0

    return {
        'url_length': int(url_length),
        'dot_count': int(dot_count),
        'hyphen_count': int(hyphen_count),
        'at_symbol': int(at_symbol),
        'double_slash_redirect': int(double_slash_redirect),
        'has_ip_address': int(has_ip),
        'subdomain_count': int(subdomain_count),
        'domain_length': int(domain_length),
        'https_flag': int(https_flag),
        'suspicious_words': int(suspicious_words)
    }


if __name__ == '__main__':
    # Test cases
    test_urls = [
        "https://www.google.com",
        "http://192.168.1.1/login/verify-account",
        "https://mparivahan.redirectme.net/6/RTO.MoRTH",
        "http://secure-update-banking.com@badsite.ru//redirect/auth"
    ]
    for u in test_urls:
        print(f"\nURL: {u}")
        print(extract_features(u))
