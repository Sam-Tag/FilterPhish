#!/usr/bin/env python3
"""
Lightweight Phishing Detection System
Uses content analysis and ML-based similarity without requiring browser automation
"""

import csv
import requests
import re
import json
from urllib.parse import urlparse
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
import numpy as np
from collections import Counter
import time

class LightweightPhishingDetector:
    def __init__(self):
        self.brand_map = self.load_brand_map()
        self.vectorizer = TfidfVectorizer(max_features=500, stop_words='english')
        
        # Phishing indicators patterns
        self.phishing_patterns = {
            'urgent_words': ['urgent', 'immediate', 'expire', 'suspend', 'verify now', 'act now'],
            'financial_words': ['account', 'login', 'password', 'verify', 'confirm', 'update', 'secure'],
            'suspicious_forms': ['password', 'credit card', 'ssn', 'social security'],
            'redirect_patterns': ['bit.ly', 'tinyurl', 'short.link', 'redirect']
        }
    
    def load_brand_map(self):
        """Load brand mappings"""
        brand_map = {}
        with open('brand_map.csv', 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                keyword = row['keyword'].strip()
                canonical_url = row['canonical_url'].strip()
                brand_map[keyword] = canonical_url
        return brand_map
    
    def get_page_content(self, url):
        """Fetch and analyze page content"""
        try:
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            
            response = requests.get(url, headers=headers, timeout=15, verify=False, allow_redirects=True)
            
            # Extract various elements
            content = response.text
            
            return {
                'status_code': response.status_code,
                'content': content,
                'final_url': response.url,
                'title': self.extract_title(content),
                'meta_description': self.extract_meta_description(content),
                'forms': self.analyze_forms(content),
                'links': self.extract_links(content),
                'text_content': self.extract_text_content(content),
                'suspicious_elements': self.find_suspicious_elements(content),
                'ssl_info': self.check_ssl_indicators(response),
                'redirects': len(response.history)
            }
        except requests.exceptions.SSLError:
            return {'error': 'SSL Certificate Error', 'status_code': 0, 'ssl_issue': True}
        except requests.exceptions.Timeout:
            return {'error': 'Timeout', 'status_code': 0}
        except Exception as e:
            return {'error': str(e), 'status_code': 0}
    
    def extract_title(self, html):
        """Extract page title"""
        match = re.search(r'<title[^>]*>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
        return match.group(1).strip() if match else ""
    
    def extract_meta_description(self, html):
        """Extract meta description"""
        match = re.search(r'<meta[^>]*name=["\']description["\'][^>]*content=["\']([^"\']*)["\']', html, re.IGNORECASE)
        return match.group(1) if match else ""
    
    def extract_text_content(self, html):
        """Extract clean text content"""
        # Remove script and style elements
        text = re.sub(r'<script[^>]*>.*?</script>', '', html, flags=re.DOTALL | re.IGNORECASE)
        text = re.sub(r'<style[^>]*>.*?</style>', '', text, flags=re.DOTALL | re.IGNORECASE)
        # Remove HTML tags
        text = re.sub(r'<[^>]+>', ' ', text)
        # Clean whitespace
        text = re.sub(r'\s+', ' ', text).strip()
        return text
    
    def analyze_forms(self, html):
        """Analyze forms for suspicious patterns"""
        forms = re.findall(r'<form[^>]*>(.*?)</form>', html, re.IGNORECASE | re.DOTALL)
        
        form_analysis = []
        for form in forms:
            inputs = re.findall(r'<input[^>]*>', form, re.IGNORECASE)
            
            # Analyze input types
            input_types = []
            for inp in inputs:
                type_match = re.search(r'type=["\']([^"\']*)["\']', inp, re.IGNORECASE)
                if type_match:
                    input_types.append(type_match.group(1).lower())
            
            form_analysis.append({
                'input_count': len(inputs),
                'input_types': input_types,
                'has_password': 'password' in input_types,
                'has_email': 'email' in input_types,
                'has_hidden': 'hidden' in input_types,
                'action_url': self.extract_form_action(form),
                'method': self.extract_form_method(form)
            })
        
        return form_analysis
    
    def extract_form_action(self, form):
        """Extract form action URL"""
        match = re.search(r'action=["\']([^"\']*)["\']', form, re.IGNORECASE)
        return match.group(1) if match else ""
    
    def extract_form_method(self, form):
        """Extract form method"""
        match = re.search(r'method=["\']([^"\']*)["\']', form, re.IGNORECASE)
        return match.group(1).lower() if match else "get"
    
    def extract_links(self, html):
        """Extract and analyze links"""
        links = re.findall(r'href=["\']([^"\']*)["\']', html, re.IGNORECASE)
        
        external_links = []
        suspicious_links = []
        
        for link in links:
            if link.startswith(('http://', 'https://')):
                external_links.append(link)
                # Check for suspicious redirect services
                if any(pattern in link for pattern in self.phishing_patterns['redirect_patterns']):
                    suspicious_links.append(link)
        
        return {
            'total_links': len(links),
            'external_links': external_links[:10],  # Limit output
            'suspicious_links': suspicious_links
        }
    
    def find_suspicious_elements(self, html):
        """Find suspicious elements in HTML"""
        suspicious = []
        
        # Check for iframes (often used in phishing)
        iframes = re.findall(r'<iframe[^>]*>', html, re.IGNORECASE)
        if iframes:
            suspicious.append(f"Contains {len(iframes)} iframe(s)")
        
        # Check for JavaScript redirects
        js_redirects = re.findall(r'window\.location|document\.location|location\.href', html, re.IGNORECASE)
        if js_redirects:
            suspicious.append(f"JavaScript redirects detected ({len(js_redirects)})")
        
        # Check for base64 encoded content (sometimes used to hide malicious code)
        base64_content = re.findall(r'data:image/[^;]+;base64,', html, re.IGNORECASE)
        if len(base64_content) > 5:  # Many base64 images might be suspicious
            suspicious.append(f"Multiple base64 encoded images ({len(base64_content)})")
        
        return suspicious
    
    def check_ssl_indicators(self, response):
        """Check SSL and security indicators"""
        ssl_info = {}
        
        # Check if HTTPS
        ssl_info['is_https'] = response.url.startswith('https://')
        
        # Check security headers
        headers = response.headers
        ssl_info['has_hsts'] = 'strict-transport-security' in headers
        ssl_info['has_csp'] = 'content-security-policy' in headers
        ssl_info['server'] = headers.get('server', 'Unknown')
        
        return ssl_info
    
    def calculate_domain_suspicion(self, domain, keyword):
        """Calculate domain-based suspicion score"""
        score = 0
        reasons = []
        
        # Get canonical domain for comparison
        canonical_url = self.brand_map.get(keyword, '')
        if canonical_url:
            canonical_domain = urlparse(canonical_url).netloc.replace('www.', '')
            clean_domain = domain.replace('www.', '')
            
            # Exact match with canonical (legitimate)
            if clean_domain == canonical_domain:
                return 0, ["Matches canonical domain"]
            
            # Subdomain of canonical (likely legitimate)
            if clean_domain.endswith('.' + canonical_domain):
                return 0.1, ["Subdomain of canonical domain"]
            
            # Typosquatting detection
            if self.is_potential_typosquatting(clean_domain, canonical_domain):
                score += 0.4
                reasons.append("Potential typosquatting")
        
        # Domain characteristics
        if any(char.isdigit() for char in domain):
            score += 0.2
            reasons.append("Contains numbers")
        
        if len(domain.split('.')) > 3:
            score += 0.2
            reasons.append("Multiple subdomains")
        
        # Suspicious TLDs
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.click', '.download', '.zip']
        if any(domain.endswith(tld) for tld in suspicious_tlds):
            score += 0.3
            reasons.append("Suspicious TLD")
        
        # Length analysis
        if len(domain) > 30:
            score += 0.1
            reasons.append("Very long domain")
        
        return min(score, 1.0), reasons
    
    def is_potential_typosquatting(self, domain, canonical):
        """Detect potential typosquatting"""
        # Remove TLD for comparison
        domain_base = domain.split('.')[0]
        canonical_base = canonical.split('.')[0]
        
        # Character substitution patterns
        substitutions = {
            'o': ['0', 'ο'], 'i': ['1', 'l', 'ι'], 'a': ['@', 'α'], 
            'e': ['3', 'ε'], 'u': ['υ'], 'n': ['η'], 'm': ['μ']
        }
        
        # Check for character substitutions
        for original, subs in substitutions.items():
            if original in canonical_base:
                for sub in subs:
                    if sub in domain_base and original not in domain_base:
                        return True
        
        # Check for character insertion/deletion (edit distance = 1)
        if abs(len(domain_base) - len(canonical_base)) == 1:
            longer = domain_base if len(domain_base) > len(canonical_base) else canonical_base
            shorter = canonical_base if len(domain_base) > len(canonical_base) else domain_base
            
            for i in range(len(longer)):
                if longer[:i] + longer[i+1:] == shorter:
                    return True
        
        return False
    
    def analyze_content_similarity(self, content1, content2):
        """Analyze content similarity using TF-IDF"""
        try:
            if not content1 or not content2:
                return 0
            
            # Clean content
            clean1 = re.sub(r'[^\w\s]', ' ', content1.lower())
            clean2 = re.sub(r'[^\w\s]', ' ', content2.lower())
            
            # Vectorize
            vectors = self.vectorizer.fit_transform([clean1, clean2])
            similarity = cosine_similarity(vectors[0:1], vectors[1:2])[0][0]
            
            return similarity
        except:
            return 0
    
    def calculate_content_suspicion(self, content_info, keyword):
        """Calculate content-based suspicion score"""
        score = 0
        reasons = []
        
        if content_info.get('error'):
            if content_info.get('ssl_issue'):
                score += 0.3
                reasons.append("SSL certificate issues")
            return min(score + 0.2, 1.0), reasons + ["Site inaccessible"]
        
        # Analyze text content
        text_content = content_info.get('text_content', '').lower()
        
        # Check for urgent/phishing language
        urgent_count = sum(1 for word in self.phishing_patterns['urgent_words'] if word in text_content)
        if urgent_count > 0:
            score += min(urgent_count * 0.1, 0.3)
            reasons.append(f"Urgent language detected ({urgent_count} instances)")
        
        # Check for financial keywords
        financial_count = sum(1 for word in self.phishing_patterns['financial_words'] if word in text_content)
        if financial_count > 3:
            score += 0.2
            reasons.append(f"Multiple financial keywords ({financial_count})")
        
        # Analyze forms
        forms = content_info.get('forms', [])
        for form in forms:
            if form.get('has_password') and form.get('has_email'):
                score += 0.3
                reasons.append("Login form detected")
            
            # Check form action
            action = form.get('action_url', '')
            if action and not action.startswith(('/', '#', '?')):
                # External form action
                score += 0.2
                reasons.append("External form submission")
        
        # Check suspicious elements
        suspicious_elements = content_info.get('suspicious_elements', [])
        if suspicious_elements:
            score += len(suspicious_elements) * 0.1
            reasons.extend(suspicious_elements)
        
        # SSL and security checks
        ssl_info = content_info.get('ssl_info', {})
        if not ssl_info.get('is_https'):
            score += 0.2
            reasons.append("No HTTPS")
        
        # Multiple redirects
        redirects = content_info.get('redirects', 0)
        if redirects > 2:
            score += 0.1
            reasons.append(f"Multiple redirects ({redirects})")
        
        return min(score, 1.0), reasons
    
    def analyze_domain(self, domain, keyword):
        """Complete domain analysis"""
        print(f"Analyzing: {domain}")
        
        # Domain-based analysis
        domain_score, domain_reasons = self.calculate_domain_suspicion(domain, keyword)
        
        # Content analysis
        content_info = self.get_page_content(domain)
        content_score, content_reasons = self.calculate_content_suspicion(content_info, keyword)
        
        # Compare with legitimate site if available
        similarity_score = 0
        canonical_url = self.brand_map.get(keyword)
        if canonical_url and not content_info.get('error'):
            legitimate_content = self.get_page_content(canonical_url)
            if not legitimate_content.get('error'):
                similarity_score = self.analyze_content_similarity(
                    content_info.get('text_content', ''),
                    legitimate_content.get('text_content', '')
                )
        
        # Calculate final risk score
        final_score = (domain_score * 0.4 + content_score * 0.5 + (1 - similarity_score) * 0.1)
        
        # Determine if phishing
        is_phishing = final_score > 0.6
        
        return {
            'domain': domain,
            'keyword': keyword,
            'domain_score': round(domain_score, 3),
            'content_score': round(content_score, 3),
            'similarity_score': round(similarity_score, 3),
            'final_risk_score': round(final_score, 3),
            'is_phishing': is_phishing,
            'domain_reasons': domain_reasons,
            'content_reasons': content_reasons,
            'title': content_info.get('title', ''),
            'status_code': content_info.get('status_code', 0),
            'has_forms': bool(content_info.get('forms')),
            'is_https': content_info.get('ssl_info', {}).get('is_https', False),
            'error': content_info.get('error')
        }
    
    def process_candidates(self, filename, limit=50):
        """Process candidate domains"""
        results = []
        
        with open(filename, 'r') as f:
            reader = csv.DictReader(f)
            candidates = list(reader)
        
        print(f"Processing {min(limit, len(candidates))} candidates...")
        
        for i, row in enumerate(candidates[:limit]):
            if i > 0 and i % 10 == 0:
                print(f"Processed {i}/{min(limit, len(candidates))} domains...")
                time.sleep(1)  # Rate limiting
            
            domain = row['Domains'].strip()
            keyword = row['Keyword Found'].strip()
            
            try:
                result = self.analyze_domain(domain, keyword)
                result.update({
                    'detection_method': row['Detected by'],
                    'monitoring_date': row['Monitoring Date']
                })
                results.append(result)
            except Exception as e:
                print(f"Error analyzing {domain}: {e}")
                results.append({
                    'domain': domain,
                    'keyword': keyword,
                    'error': str(e),
                    'final_risk_score': 0.5
                })
        
        return results
    
    def save_results(self, results, filename='lightweight_phishing_analysis.csv'):
        """Save analysis results"""
        if not results:
            return
        
        fieldnames = [
            'domain', 'keyword', 'final_risk_score', 'is_phishing',
            'domain_score', 'content_score', 'similarity_score',
            'domain_reasons', 'content_reasons', 'title', 'status_code',
            'has_forms', 'is_https', 'detection_method', 'monitoring_date', 'error'
        ]
        
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            
            for result in results:
                # Convert lists to strings
                if 'domain_reasons' in result:
                    result['domain_reasons'] = '; '.join(result['domain_reasons'])
                if 'content_reasons' in result:
                    result['content_reasons'] = '; '.join(result['content_reasons'])
                writer.writerow(result)
        
        print(f"Results saved to {filename}")

def main():
    detector = LightweightPhishingDetector()
    
    # Process candidates
    results = detector.process_candidates('candidates.csv', limit=30)  # Limit for demo
    
    # Save results
    detector.save_results(results)
    
    # Print summary
    successful_analyses = [r for r in results if not r.get('error')]
    phishing_count = sum(1 for r in successful_analyses if r.get('is_phishing'))
    high_risk_count = sum(1 for r in successful_analyses if r.get('final_risk_score', 0) > 0.7)
    
    print(f"\n=== ANALYSIS SUMMARY ===")
    print(f"Total processed: {len(results)}")
    print(f"Successful analyses: {len(successful_analyses)}")
    print(f"Identified as phishing: {phishing_count}")
    print(f"High risk (>0.7): {high_risk_count}")
    
    # Show top risks
    sorted_results = sorted(successful_analyses, key=lambda x: x.get('final_risk_score', 0), reverse=True)
    print(f"\nTop 10 highest risk domains:")
    for i, result in enumerate(sorted_results[:10]):
        reasons = result.get('domain_reasons', []) + result.get('content_reasons', [])
        if isinstance(reasons, str):
            reasons = reasons.split('; ')
        print(f"{i+1}. {result['domain']} - Risk: {result['final_risk_score']} - "
              f"Phishing: {result['is_phishing']}")
        if reasons:
            print(f"   Reasons: {', '.join(reasons[:3])}")

if __name__ == "__main__":
    main()