#!/usr/bin/env python3
import csv

# Load brand mappings
brand_domains = {}
with open('brand_map.csv', 'r') as f:
    reader = csv.DictReader(f)
    for row in reader:
        keyword = row['keyword'].strip()
        url = row['canonical_url'].strip()
        # Extract domain from URL
        if url.startswith('https://'):
            domain = url.replace('https://', '').replace('www.', '')
        brand_domains[keyword] = domain

print("Brand mappings loaded:")
for k, v in list(brand_domains.items())[:5]:
    print(f"  {k} -> {v}")

# Analyze candidates
suspicious = []
whitelisted = []

with open('candidates.csv', 'r') as f:
    reader = csv.DictReader(f)
    for row in reader:
        domain = row['Domains'].strip()
        keyword = row['Keyword Found'].strip()
        
        # Check if domain matches canonical domain
        canonical = brand_domains.get(keyword, '')
        
        is_legitimate = False
        if canonical:
            # Remove www. for comparison
            clean_domain = domain.replace('www.', '')
            clean_canonical = canonical.replace('www.', '')
            
            # Exact match or subdomain
            if clean_domain == clean_canonical or clean_domain.endswith('.' + clean_canonical):
                is_legitimate = True
        
        if is_legitimate:
            whitelisted.append(row)
        else:
            suspicious.append(row)

print(f"\nResults:")
print(f"Total candidates: {len(suspicious) + len(whitelisted)}")
print(f"Suspicious: {len(suspicious)}")
print(f"Whitelisted: {len(whitelisted)}")

# Show some examples
print(f"\nTop 10 suspicious domains:")
for i, row in enumerate(suspicious[:10]):
    print(f"{i+1}. {row['Domains']} (keyword: {row['Keyword Found']})")

if whitelisted:
    print(f"\nWhitelisted domains:")
    for row in whitelisted:
        print(f"  {row['Domains']} -> {row['Keyword Found']}")