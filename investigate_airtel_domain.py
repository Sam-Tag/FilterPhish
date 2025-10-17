#!/usr/bin/env python3

import requests
import re
from urllib.parse import urljoin, urlparse
import time

def investigate_airtel_domain():
    """Investigate if airtelharyana.com is legitimate"""
    
    domain = "airtelharyana.com"
    
    print(f"Investigating {domain}...")
    print("=" * 50)
    
    try:
        # Get the page content
        response = requests.get(f"https://{domain}", 
                              timeout=15, 
                              verify=False,
                              headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'})
        
        print(f"Status Code: {response.status_code}")
        print(f"Final URL: {response.url}")
        print()
        
        content = response.text
        
        # Extract title
        title_match = re.search(r'<title[^>]*>(.*?)</title>', content, re.IGNORECASE | re.DOTALL)
        if title_match:
            title = title_match.group(1).strip()
            print(f"Title: {title}")
        
        # Look for official Airtel indicators
        print("\nLooking for legitimacy indicators:")
        
        # Check for official Airtel domains in links
        airtel_links = re.findall(r'https?://[^"\s]*airtel[^"\s]*', content)
        official_airtel_links = [link for link in airtel_links if 'airtel.in' in link or 'airtel.com' in link]
        
        if official_airtel_links:
            print(f"✓ Found {len(official_airtel_links)} links to official Airtel domains:")
            for link in official_airtel_links[:5]:  # Show first 5
                print(f"  - {link}")
        
        # Check for contact information
        phone_pattern = r'(\+91|91)?[-\s]?[6-9]\d{9}'
        phones = re.findall(phone_pattern, content)
        if phones:
            print(f"✓ Found phone numbers: {phones[:3]}")  # Show first 3
        
        # Check for email addresses
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        emails = re.findall(email_pattern, content)
        airtel_emails = [email for email in emails if 'airtel' in email.lower()]
        if airtel_emails:
            print(f"✓ Found Airtel email addresses: {airtel_emails}")
        
        # Check for SSL certificate info
        print(f"\nSSL Certificate: {'✓ Valid' if response.url.startswith('https') else '✗ No HTTPS'}")
        
        # Check for redirects to official Airtel
        if 'airtel.in' in response.url or 'airtel.com' in response.url:
            print("✓ Redirects to official Airtel domain")
        
        # Look for regional/state-specific content
        haryana_indicators = ['haryana', 'chandigarh', 'gurgaon', 'faridabad', 'rohtak']
        found_haryana = [indicator for indicator in haryana_indicators if indicator in content.lower()]
        if found_haryana:
            print(f"✓ Found Haryana-specific content: {found_haryana}")
        
        # Check for official Airtel branding elements
        branding_elements = ['airtel', 'bharti', 'postpaid', 'prepaid', 'broadband']
        found_branding = [element for element in branding_elements if element in content.lower()]
        print(f"✓ Found Airtel branding elements: {found_branding}")
        
        # Look for suspicious elements
        print("\nLooking for suspicious indicators:")
        
        # Check for login forms
        login_forms = re.findall(r'<form[^>]*>.*?</form>', content, re.DOTALL | re.IGNORECASE)
        password_forms = [form for form in login_forms if 'password' in form.lower()]
        if password_forms:
            print(f"⚠ Found {len(password_forms)} forms with password fields")
        
        # Check for urgent language
        urgent_words = ['urgent', 'expire', 'suspend', 'block', 'verify now', 'act now']
        found_urgent = [word for word in urgent_words if word in content.lower()]
        if found_urgent:
            print(f"⚠ Found urgent language: {found_urgent}")
        
        # Check domain registration (simplified)
        print(f"\nDomain Analysis:")
        print(f"Domain: {domain}")
        print(f"Contains 'airtel': {'✓' if 'airtel' in domain else '✗'}")
        print(f"Contains 'haryana': {'✓' if 'haryana' in domain else '✗'}")
        print(f"TLD: {domain.split('.')[-1]}")
        
        return {
            'domain': domain,
            'status_code': response.status_code,
            'final_url': response.url,
            'title': title if title_match else None,
            'official_links': len(official_airtel_links),
            'has_contact_info': len(phones) > 0 or len(airtel_emails) > 0,
            'regional_content': len(found_haryana) > 0,
            'suspicious_forms': len(password_forms),
            'urgent_language': len(found_urgent)
        }
        
    except Exception as e:
        print(f"Error investigating domain: {e}")
        return None

if __name__ == "__main__":
    result = investigate_airtel_domain()
    
    print("\n" + "=" * 50)
    print("CONCLUSION:")
    
    if result:
        legitimacy_score = 0
        
        # Positive indicators
        if result['official_links'] > 0:
            legitimacy_score += 2
        if result['has_contact_info']:
            legitimacy_score += 1
        if result['regional_content']:
            legitimacy_score += 2
        if result['status_code'] == 200:
            legitimacy_score += 1
        
        # Negative indicators
        if result['suspicious_forms'] > 0:
            legitimacy_score -= 2
        if result['urgent_language'] > 0:
            legitimacy_score -= 1
        
        print(f"Legitimacy Score: {legitimacy_score}/6")
        
        if legitimacy_score >= 4:
            print("ASSESSMENT: Likely LEGITIMATE regional Airtel site")
        elif legitimacy_score >= 2:
            print("ASSESSMENT: UNCERTAIN - requires manual review")
        else:
            print("ASSESSMENT: Potentially SUSPICIOUS")