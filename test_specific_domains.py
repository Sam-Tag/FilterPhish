#!/usr/bin/env python3
"""
Test specific phishing domains mentioned by user
"""

import csv
from advanced_phishing_detector import PhishingDetector

def test_specific_domains():
    """Test the specific domains mentioned by user"""
    
    # Domains that should be flagged as phishing
    test_domains = [
        ('dc.crsorgi.gov.in.viewcertificates.xyz', 'dc.crsorgi.gov'),
        ('sbiyono.link', 'sbi'),
        ('yonosbionline.link', 'sbi'),
        ('yono-sbi-online.ws', 'sbi'),
        ('sbi-yono-business.ws', 'sbi'),
        ('estudioclq.com', 'iocl'),  # Should NOT be flagged (no relevant content)
    ]
    
    detector = PhishingDetector()
    
    print("Testing specific domains mentioned by user:")
    print("=" * 60)
    
    for domain, keyword in test_domains:
        print(f"\nTesting: {domain} (keyword: {keyword})")
        
        try:
            result = detector.analyze_domain(domain, keyword)
            
            risk_score = result.get('risk_score', 0)
            is_phishing = result.get('is_phishing', False)
            indicators = result.get('llm_indicators', [])
            
            print(f"Risk Score: {risk_score}")
            print(f"Is Phishing: {is_phishing}")
            print(f"Indicators: {indicators[:3]}")  # Show first 3 indicators
            
            # Expected results
            if domain == 'estudioclq.com':
                expected = "Should be LOW risk (no banking content)"
            else:
                expected = "Should be HIGH risk (phishing attempt)"
            
            print(f"Expected: {expected}")
            
            if is_phishing:
                print("✅ CORRECTLY IDENTIFIED AS PHISHING")
            else:
                print("❌ NOT IDENTIFIED AS PHISHING")
                
        except Exception as e:
            print(f"Error analyzing {domain}: {e}")
        
        print("-" * 40)
    
    detector.cleanup()

if __name__ == "__main__":
    test_specific_domains()