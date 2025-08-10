# feature_extraction.py

import re
import urllib.parse

def extract_all_features(url, for_training=False):
    try:
        parsed = urllib.parse.urlparse(url)
        netloc = parsed.netloc
        path = parsed.path

        features = {
            'hasIpAddress': has_ip(url),
            'urlLength': len(url),
            'hasAtSymbol': int("@" in url),
            'hasDoubleSlash': int(url.count("//") > 1),
            'numDots': netloc.count('.'),
            'hasHttps': int(url.startswith('https')),
            'subdomainDepth': len(netloc.split('.')) - 2,
            'pathDepth': path.count('/'),
            'hasSensitiveWords': has_sensitive_words(url),
            'hasHyphen': int('-' in netloc),
            'isSuspiciousTld': is_suspicious_tld(netloc),
            'isShortened': is_shortened(url),
            'brandInSubdomainNotDomain': brand_in_subdomain_not_domain(netloc),
            'hasEncodedChars': int('%' in url or '\\x' in url),
        }

        # Add verdict only if not training
        if not for_training:
            score = 0
            score += 2 * features['hasIpAddress']
            score += 2 * features['hasSensitiveWords']
            score += 1.5 * features['hasHyphen']
            score += 2 * features['isShortened']
            score += 3 * features['brandInSubdomainNotDomain']
            score += -0.5 if features['hasHttps'] == 0 else 0

            features['threatConfidence'] = round(min(max(score * 20, 0), 100), 2)
            features['verdict'] = 'Phishing' if score >= 3.5 else 'Likely Safe'

        return features
    except Exception as e:
        print(f"[Feature Extraction Error] {e}")
        return None

# === Feature helper functions ===

def has_ip(url):
    return int(bool(re.search(r'http[s]?://\d+\.\d+\.\d+\.\d+', url)))

def has_sensitive_words(url):
    keywords = ['secure', 'account', 'update', 'free', 'login', 'ebayisapi', 'webscr', 'signin', 'banking']
    return int(any(word in url.lower() for word in keywords))

def is_shortened(url):
    shorteners = r"(bit\.ly|goo\.gl|tinyurl\.com|ow\.ly|t\.co|is\.gd|buff\.ly)"
    return int(bool(re.search(shorteners, url)))

def is_suspicious_tld(hostname):
    suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top']
    return int(any(hostname.endswith(tld) for tld in suspicious_tlds))

def brand_in_subdomain_not_domain(hostname):
    brands = ['paypal', 'google', 'hsbc', 'amazon', 'microsoft', 'netflix', 'facebook', 'gmail', 'apple']
    parts = hostname.split('.')
    if len(parts) < 2:
        return 0
    subdomains = '.'.join(parts[:-2])
    domain = parts[-2]
    for brand in brands:
        if brand in subdomains and brand != domain:
            return 1
    return 0
