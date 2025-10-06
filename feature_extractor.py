import re
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin

# Common sensitive words and brands list
SENSITIVE_WORDS = ["login", "secure", "account", "update", "verify", "password", "bank", "crypto", "web3"]
BRAND_NAMES = ["paypal", "sbi", "hdfc", "amazon", "apple", "microsoft", "google"]

def extract_features(url):
    """
    Extracts 31 phishing-related features from a given URL.
    This corrected version properly handles relative vs. absolute paths for links and resources.
    """
    features = {f: 0 for f in [
        'PctExtHyperlinks', 'PctExtResourceUrls', 'PctNullSelfRedirectHyperlinks',
        'PctExtNullSelfRedirectHyperlinksRT', 'NumNumericChars', 'FrequentDomainNameMismatch',
        'ExtMetaScriptLinkRT', 'NumDash', 'SubmitInfoToEmail', 'NumDots', 'PathLength',
        'QueryLength', 'PathLevel', 'InsecureForms', 'UrlLength', 'NumSensitiveWords',
        'NumQueryComponents', 'PctExtResourceUrlsRT', 'IframeOrFrame', 'HostnameLength',
        'NumAmpersand', 'AbnormalExtFormActionR', 'UrlLengthRT', 'NumDashInHostname',
        'IpAddress', 'AbnormalFormAction', 'EmbeddedBrandName', 'NumUnderscore',
        'MissingTitle', 'DomainInPaths', 'SubdomainLevel', 'ExtFormAction'
    ]}

    try:
        # --- Initial URL Parsing ---
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname or ""
        path = parsed_url.path or ""
        query = parsed_url.query or ""
        domain_netloc = parsed_url.netloc

        # --- 1. URL-based Features ---
        features['NumNumericChars'] = sum(c.isdigit() for c in url)
        features['NumDash'] = url.count('-')
        features['NumDots'] = url.count('.')
        features['PathLength'] = len(path)
        features['QueryLength'] = len(query)
        features['PathLevel'] = path.count('/')
        features['UrlLength'] = len(url)
        features['NumQueryComponents'] = len(query.split('&')) if query else 0
        features['HostnameLength'] = len(hostname)
        features['NumAmpersand'] = url.count('&')
        # Adding 1 to denominator to avoid division by zero
        features['UrlLengthRT'] = len(url) / (len(hostname) + 1)
        features['NumDashInHostname'] = hostname.count('-')
        features['IpAddress'] = 1 if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname) else 0
        features['NumUnderscore'] = url.count('_')
        # Check if the primary domain name appears in the path
        main_domain = hostname.split('.')[-2] if hostname.count('.') > 0 else hostname
        features['DomainInPaths'] = 1 if main_domain in path else 0
        features['SubdomainLevel'] = hostname.count('.') -1 if hostname.count('.') > 1 else 0
        # Correctly casts boolean to integer (1 or 0)
        features['EmbeddedBrandName'] = int(any(b in url.lower() for b in BRAND_NAMES))

        # --- 2. Content-based Features ---
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36'}
        resp = requests.get(url, timeout=5, headers=headers)
        html_content = resp.text
        soup = BeautifulSoup(html_content, "html.parser")

        # Title check
        features['MissingTitle'] = 1 if not soup.title or not soup.title.string.strip() else 0

        # Sensitive words in content
        page_text_lower = html_content.lower()
        features['NumSensitiveWords'] = sum(word in page_text_lower for word in SENSITIVE_WORDS)

        # Iframe/Frame check
        features['IframeOrFrame'] = 1 if soup.find("iframe") or soup.find("frame") else 0

        # --- Helper function for robustly checking external URLs ---
        def is_external(link_url):
            if not link_url or link_url.startswith("mailto:") or link_url.startswith("javascript:"):
                return False
            # Create an absolute URL from the found link
            absolute_link = urljoin(url, link_url)
            # Parse the absolute link and compare its domain
            link_netloc = urlparse(absolute_link).netloc
            return link_netloc != '' and link_netloc != domain_netloc

        # Hyperlinks analysis
        all_links = [a.get("href", "") for a in soup.find_all("a")]
        if all_links:
            num_links = len(all_links)
            null_self_links = [l for l in all_links if l in ["#", "", "javascript:void(0);", "javascript:void(0)"]]
            external_links = [l for l in all_links if is_external(l)]

            features['PctExtHyperlinks'] = len(external_links) / num_links
            features['PctNullSelfRedirectHyperlinks'] = len(null_self_links) / num_links
            features['PctExtNullSelfRedirectHyperlinksRT'] = (len(external_links) + len(null_self_links)) / num_links

        # Resource URLs analysis (img, script, link)
        resource_tags = soup.find_all(["img", "script", "link"])
        all_resources = [tag.get("src", "") or tag.get("href", "") for tag in resource_tags]
        if all_resources:
            num_resources = len(all_resources)
            external_resources = [r for r in all_resources if is_external(r)]

            features['PctExtResourceUrls'] = len(external_resources) / num_resources
            # PctExtResourceUrlsRT is often defined similarly or related to external resources.
            # Here, it's calculated the same way, as the original code did.
            features['PctExtResourceUrlsRT'] = len(external_resources) / num_resources

        # Meta/Script/Link tag analysis
        meta_script_link_tags = soup.find_all(["meta", "script", "link"])
        all_msl = [tag.get("src", "") or tag.get("href", "") for tag in meta_script_link_tags]
        if all_msl:
            num_msl = len(all_msl)
            external_msl = [m for m in all_msl if is_external(m)]
            features['ExtMetaScriptLinkRT'] = len(external_msl) / num_msl

        # Form analysis
        forms = soup.find_all("form")
        for form in forms:
            action = form.get("action", "")
            if "mailto:" in action:
                features['SubmitInfoToEmail'] = 1
            if action.strip().startswith("http://"):
                features['InsecureForms'] = 1

            if is_external(action):
                features['AbnormalFormAction'] = 1
                features['AbnormalExtFormActionR'] += 1 # Count of abnormal actions
                if action.startswith("http"):
                    features['ExtFormAction'] = 1

    except Exception as e:
        print(f"Error extracting features for {url}: {e}")
        # Return the initialized dictionary in case of an error
        features['FetchFailed'] = 1
        return features

    return features


if __name__ == "__main__":
    phishing_url = "https://jitoget.com"
    phishing_features = extract_features(phishing_url)
    print(phishing_features)
