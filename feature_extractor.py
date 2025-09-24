import re
import tldextract
from urllib.parse import urlparse

def extract_features (url):
    parsed = urlparse(url if "://" in url else "http://" + url)
    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""
    full = url if isinstance(url, str) else str(url)

    num_digits = sum(c.isdigit() for c in full)
    ext = tldextract.extract(full)
    subdomain_parts = ext.subdomain.split('.') if ext.subdomain else []
    subdomain_level = len([p for p in subdomain_parts if p])

    features = {
        "NumDots": hostname.count("."),
        "SubdomainLevel": max(0, subdomain_level),
        "PathLevel": path.count("/"),
        "UrlLength": len(full),
        "NumDash": full.count("-"),
        "NumDashInHostname": hostname.count("-"),
        "AtSymbol": 1 if "@" in full else 0,
        "TildeSymbol": 1 if "~" in full else 0,
        "NumUnderscore": full.count("_"),
        "NumPercent": full.count("%"),
        "NumQueryComponents": query.count("="),
        "NumAmpersand": query.count("&"),
        "NumHash": full.count("#"),
        "NumNumericChars": num_digits,
        "NoHttps": 0 if parsed.scheme == "https" else 1,
        "RandomString": 0,  # placeholder; we compute heuristic below
        "IpAddress": 1 if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname) else 0,
        "DomainInSubdomains": 1 if ext.domain and ext.domain in ext.subdomain else 0,
        "DomainInPaths": 1 if ext.domain and ext.domain in path else 0,
        "HttpsInHostname": 1 if "https" in hostname else 0,
        "HostnameLength": len(hostname),
        "PathLength": len(path),
        "QueryLength": len(query),
        "DoubleSlashInPath": 1 if "//" in path else 0
    }

    def token_entropy(s):
        import math
        from collections import Counter
        if not s:
            return 0.0
        c = Counter(s)
        probs = [v/len(s) for v in c.values()]
        return -sum(p * math.log2(p) for p in probs)

    tokens = re.split(r"[\/\-\_\?\=\&\.]", path + query)
    long_tokens = [t for t in tokens if len(t) >= 8]
    entropies = [token_entropy(t) for t in long_tokens]
    features["RandomString"] = 1 if (len(long_tokens) > 0 and max(entropies) > 3.5) else 0

    return features

print(extract_features("https://www.google.com/search?gs_ssp=eJzj4tTP1TcwMU02T1JgNGB0YPBiS8_PT89JBQBASQXT&q=google&ie=UTF-8"))
