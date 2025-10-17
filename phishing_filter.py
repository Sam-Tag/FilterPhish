#!/usr/bin/env python3
"""
Phishing Detection Filter
Filters candidate domains against whitelisted domains to reduce false positives
"""

import csv
import re
from urllib.parse import urlparse
from difflib import SequenceMatcher

def load_brand_map(filename):
    """Load the brand mapping from CSV file"""
    brand_map = {}
    with open(filename, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            keyword = row['keyword'].strip()
            canonical_url = row['canonical_url'].strip()
            # Extract domain from canonical URL
            domain = urlparse(canonical_url).netloc.lower()
            brand_map[keyword] = domain
    return brand_map

def extract_domain(url):
    """Extract domain from URL or return as-is if already a domain"""
    if url.startswith(('http://', 'https://')):
        return urlparse(url).netloc.lower()
    return url.lower()

def is_whitelisted_domain(candidate_domain, keyword, brand_map):
    """Check if candidate domain matches whitelisted domain for the keyword"""
    if keyword not in brand_map:
        return False
    
    canonical_domain = brand_map[keyword]
    candidate_clean = extract_domain(candidate_domain)
    
    # Exact match
    if candidate_clean == canonical_domain:
        return True
    
    # Check if it's a subdomain of the canonical domain
    if candidate_clean.endswith('.' + canonical_domain):
        return True
    
    return False

def similarity_score(str1, str2):
    """Calculate similarity between two strings"""
    return SequenceMatcher(None, str1, str2).ratio()

def analyze_candidates(candidates_file, brand_map):
    """Analyze candidates and filter out whitelisted domains"""
    suspicious_domains = []
    whitelisted_domains = []
    
    with open(candidates_file, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            domain = row['Domains'].strip()
            keyword = row['Keyword Found'].strip()
            detection_method = row['Detected by'].strip()
            monitoring_date = row['Monitoring Date'].strip()
            
            if is_whitelisted_domain(domain, keyword, brand_map):
                whitelisted_domains.append({
                    'domain': domain,
                    'keyword': keyword,
                    'detection_method': detection_method,
                    'monitoring_date': monitoring_date,
                    'status': 'WHITELISTED'
                })
            else:
                # Calculate similarity with canonical domain for additional context
                canonical_domain = brand_map.get(keyword, '')
                similarity = similarity_score(extract_domain(domain), canonical_domain) if canonical_domain else 0
                
                suspicious_domains.append({
                    'domain': domain,
                    'keyword': keyword,
                    'detection_method': detection_method,
                    'monitoring_date': monitoring_date,
                    'canonical_domain': canonical_domain,
                    'similarity_score': round(similarity, 3),
                    'status': 'SUSPICIOUS'
                })
    
    return suspicious_domains, whitelisted_domains

def main():
    # Load brand mapping
    brand_map = load_brand_map('brand_map.csv')
    
    print(f"Loaded {len(brand_map)} brand mappings")
    print("\nBrand mappings:")
    for keyword, domain in list(brand_map.items())[:5]:  # Show first 5
        print(f"  {keyword} -> {domain}")
    print("  ...")
    
    # Analyze candidates
    suspicious, whitelisted = analyze_candidates('candidates.csv', brand_map)
    
    print(f"\n=== ANALYSIS RESULTS ===")
    print(f"Total candidates processed: {len(suspicious) + len(whitelisted)}")
    print(f"Suspicious domains: {len(suspicious)}")
    print(f"Whitelisted domains: {len(whitelisted)}")
    
    # Save suspicious domains to new CSV
    if suspicious:
        with open('suspicious_domains.csv', 'w', newline='', encoding='utf-8') as f:
            fieldnames = ['domain', 'keyword', 'detection_method', 'monitoring_date', 
                         'canonical_domain', 'similarity_score', 'status']
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(suspicious)
        print(f"\nSuspicious domains saved to 'suspicious_domains.csv'")
    
    # Save whitelisted domains to separate CSV
    if whitelisted:
        with open('whitelisted_domains.csv', 'w', newline='', encoding='utf-8') as f:
            fieldnames = ['domain', 'keyword', 'detection_method', 'monitoring_date', 'status']
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(whitelisted)
        print(f"Whitelisted domains saved to 'whitelisted_domains.csv'")
    
    # Show top suspicious domains by similarity score
    print(f"\n=== TOP 10 MOST SUSPICIOUS DOMAINS ===")
    top_suspicious = sorted(suspicious, key=lambda x: x['similarity_score'], reverse=True)[:10]
    for domain_info in top_suspicious:
        print(f"{domain_info['domain']:<30} | {domain_info['keyword']:<15} | "
              f"Similarity: {domain_info['similarity_score']:<5} | {domain_info['detection_method']}")

if __name__ == "__main__":
    main()