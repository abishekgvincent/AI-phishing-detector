import requests
import json
import csv
from datetime import datetime

# Tranco API for top sites
TRANCO_LIST_URL = "https://tranco-list.eu/top-1m.csv"

# Extra trusted domains to always include
EXTRA_SAFE_DOMAINS = [
    "google.com", "microsoft.com", "github.com", "stackoverflow.com",
    "apple.com", "openai.com", "linkedin.com", "youtube.com",
    "paypal.com", "amazon.com", "srmist.edu.in", "nptel.ac.in",
    "coursera.org", "udemy.com", "greatlearning.in", "who.int", "un.org",
    "isro.gov.in", "nasa.gov", "gov.uk", "usa.gov"
]

def fetch_tranco_domains(limit=1000):
    """Fetches top global domains from Tranco list."""
    print("🔄 Fetching domains from Tranco...")
    response = requests.get(TRANCO_LIST_URL)
    if response.status_code != 200:
        print("❌ Failed to fetch Tranco list.")
        return []

    domains = []
    reader = csv.reader(response.text.splitlines())
    for i, row in enumerate(reader):
        if i >= limit:
            break
        domains.append(row[1])
    print(f"✅ Fetched {len(domains)} domains from Tranco.")
    return domains

def merge_domains(tranco_list, extra_list):
    """Combine and clean domains."""
    all_domains = set(tranco_list + extra_list)
    return sorted(all_domains)

def save_safe_domains(domains):
    """Save to JSON file."""
    data = {"updated_on": datetime.now().isoformat(), "safe_domains": domains}
    with open("safe_domains.json", "w") as f:
        json.dump(data, f, indent=2)
    print(f"💾 Saved {len(domains)} safe domains to safe_domains.json")

def main():
    tranco_domains = fetch_tranco_domains(limit=2000)
    merged = merge_domains(tranco_domains, EXTRA_SAFE_DOMAINS)
    save_safe_domains(merged)
    print("🎉 Safe domain list updated successfully!")

if __name__ == "__main__":
    main()
