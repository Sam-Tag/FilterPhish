#!/usr/bin/env python3
"""
Advanced Phishing Detection System
Uses ML, LLM, and visual similarity to detect phishing domains
"""

import csv
import requests
import time
from urllib.parse import urlparse
import json
import base64
from io import BytesIO
from PIL import Image
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
import re
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import hashlib

class PhishingDetector:
    def __init__(self):
        self.brand_map = self.load_brand_map()
        self.setup_browser()
        self.vectorizer = TfidfVectorizer(max_features=1000, stop_words='english')
        
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
    
    def setup_browser(self):
        """Setup headless browser for screenshots"""
        chrome_options = Options()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument("--window-size=1920,1080")
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
        
        try:
            self.driver = webdriver.Chrome(options=chrome_options)
        except Exception as e:
            print(f"Chrome driver not available: {e}")
            self.driver = None
    
    def get_page_content(self, url):
        """Fetch page content and metadata"""
        try:
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            response = requests.get(url, headers=headers, timeout=10, verify=False)
            
            return {
                'status_code': response.status_code,
                'content': response.text,
                'headers': dict(response.headers),
                'url': response.url,
                'title': self.extract_title(response.text),
                'forms': self.extract_forms(response.text),
                'links': self.extract_links(response.text),
                'keywords': self.extract_keywords(response.text)
            }
        except Exception as e:
            return {'error': str(e), 'status_code': 0}
    
    def extract_title(self, html):
        """Extract page title"""
        title_match = re.search(r'<title[^>]*>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
        return title_match.group(1).strip() if title_match else ""
    
    def extract_forms(self, html):
        """Extract form information"""
        forms = re.findall(r'<form[^>]*>(.*?)</form>', html, re.IGNORECASE | re.DOTALL)
        form_data = []
        for form in forms:
            inputs = re.findall(r'<input[^>]*>', form, re.IGNORECASE)
            form_data.append({
                'input_count': len(inputs),
                'has_password': 'password' in form.lower(),
                'has_email': 'email' in form.lower() or '@' in form,
                'action': re.search(r'action=["\']([^"\']*)["\']', form, re.IGNORECASE)
            })
        return form_data
    
    def extract_links(self, html):
        """Extract external links"""
        links = re.findall(r'href=["\']([^"\']*)["\']', html, re.IGNORECASE)
        external_links = [link for link in links if link.startswith(('http://', 'https://'))]
        return external_links[:10]  # Limit to first 10
    
    def extract_keywords(self, html):
        """Extract relevant keywords from HTML with enhanced brand detection"""
        # Remove HTML tags but preserve text
        text = re.sub(r'<[^>]+>', ' ', html)
        
        # Extract financial/banking keywords
        financial_keywords = re.findall(
            r'\b(login|password|account|bank|banking|card|otp|verify|secure|payment|transfer|'
            r'netbanking|mobile banking|yono|digital banking|online banking|verification|'
            r'authenticate|signin|register|deposit|withdraw|balance|statement)\b', 
            text, re.IGNORECASE
        )
        
        # Extract brand-specific keywords
        brand_keywords = re.findall(
            r'\b(sbi|icici|hdfc|axis|kotak|pnb|bob|canara|union|indian|oil|airtel|jio|'
            r'government|gov|official|ministry|department)\b',
            text, re.IGNORECASE
        )
        
        # Extract urgency keywords
        urgency_keywords = re.findall(
            r'\b(urgent|immediate|expire|suspend|block|deactivate|temporary|alert|'
            r'action required|verify now|update now|confirm now)\b',
            text, re.IGNORECASE
        )
        
        all_keywords = financial_keywords + brand_keywords + urgency_keywords
        return list(set([kw.lower() for kw in all_keywords]))
    
    def take_screenshot(self, url):
        """Take screenshot of the webpage"""
        if not self.driver:
            return None
            
        try:
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
                
            self.driver.get(url)
            time.sleep(3)  # Wait for page load
            
            screenshot = self.driver.get_screenshot_as_png()
            return screenshot
        except Exception as e:
            print(f"Screenshot failed for {url}: {e}")
            return None
    
    def compare_visual_similarity(self, img1_data, img2_data):
        """Compare visual similarity between two images"""
        try:
            img1 = Image.open(BytesIO(img1_data)).convert('RGB')
            img2 = Image.open(BytesIO(img2_data)).convert('RGB')
            
            # Resize to same dimensions
            size = (300, 200)
            img1 = img1.resize(size)
            img2 = img2.resize(size)
            
            # Convert to numpy arrays
            arr1 = np.array(img1)
            arr2 = np.array(img2)
            
            # Calculate structural similarity
            mse = np.mean((arr1 - arr2) ** 2)
            similarity = 1 / (1 + mse / 1000)  # Normalize
            
            return similarity
        except Exception as e:
            print(f"Visual comparison failed: {e}")
            return 0
    
    def analyze_content_similarity(self, content1, content2):
        """Enhanced content similarity analysis with context awareness"""
        try:
            if not content1 or not content2:
                return 0
            
            # Clean and preprocess content
            clean1 = self.preprocess_content_for_similarity(content1)
            clean2 = self.preprocess_content_for_similarity(content2)
            
            if not clean1 or not clean2:
                return 0
            
            # Use TF-IDF for semantic similarity
            vectors = self.vectorizer.fit_transform([clean1, clean2])
            tfidf_similarity = cosine_similarity(vectors[0:1], vectors[1:2])[0][0]
            
            # Additional context-based similarity
            context_similarity = self.calculate_context_similarity(content1, content2)
            
            # Weighted combination
            final_similarity = (tfidf_similarity * 0.7) + (context_similarity * 0.3)
            
            return final_similarity
        except Exception as e:
            print(f"Content similarity analysis failed: {e}")
            return 0
    
    def preprocess_content_for_similarity(self, content):
        """Preprocess content for better similarity analysis"""
        if not content:
            return ""
        
        # Remove HTML tags
        text = re.sub(r'<[^>]+>', ' ', content)
        
        # Convert to lowercase
        text = text.lower()
        
        # Remove special characters but keep important punctuation
        text = re.sub(r'[^\w\s.,!?-]', ' ', text)
        
        # Remove extra whitespace
        text = re.sub(r'\s+', ' ', text).strip()
        
        # Remove very short words (less than 3 characters) except important ones
        important_short_words = {'sbi', 'otp', 'atm', 'kyc', 'pan', 'upi'}
        words = text.split()
        filtered_words = [
            word for word in words 
            if len(word) >= 3 or word in important_short_words
        ]
        
        return ' '.join(filtered_words)
    
    def calculate_context_similarity(self, content1, content2):
        """Calculate similarity based on banking/financial context"""
        try:
            # Define context categories
            banking_terms = [
                'account', 'balance', 'transaction', 'transfer', 'deposit',
                'withdraw', 'statement', 'branch', 'customer', 'service'
            ]
            
            digital_terms = [
                'online', 'mobile', 'app', 'digital', 'internet', 'web',
                'login', 'password', 'otp', 'secure', 'authentication'
            ]
            
            financial_terms = [
                'bank', 'banking', 'finance', 'money', 'payment', 'card',
                'loan', 'credit', 'debit', 'savings', 'investment'
            ]
            
            # Count terms in each content
            def count_terms(content, terms):
                content_lower = content.lower()
                return sum(1 for term in terms if term in content_lower)
            
            # Calculate category similarities
            banking_sim = min(count_terms(content1, banking_terms), count_terms(content2, banking_terms)) / max(
                max(count_terms(content1, banking_terms), count_terms(content2, banking_terms)), 1
            )
            
            digital_sim = min(count_terms(content1, digital_terms), count_terms(content2, digital_terms)) / max(
                max(count_terms(content1, digital_terms), count_terms(content2, digital_terms)), 1
            )
            
            financial_sim = min(count_terms(content1, financial_terms), count_terms(content2, financial_terms)) / max(
                max(count_terms(content1, financial_terms), count_terms(content2, financial_terms)), 1
            )
            
            # Weighted average
            context_similarity = (banking_sim * 0.4) + (digital_sim * 0.3) + (financial_sim * 0.3)
            
            return context_similarity
            
        except Exception as e:
            print(f"Context similarity calculation failed: {e}")
            return 0
    
    def llm_phishing_analysis(self, domain_info, legitimate_content):
        """Enhanced LLM-style analysis for advanced phishing detection"""
        suspicious_indicators = []
        risk_score = 0.0
        
        # Domain analysis
        domain = domain_info.get('domain', '')
        keyword = domain_info.get('keyword', '')
        content_info = domain_info.get('content_info', {})
        
        # Get canonical domain for comparison
        canonical_domain = self.brand_map.get(keyword, '').replace('https://', '').replace('www.', '')
        
        # CRITICAL PHISHING PATTERNS (High Weight)
        
        # 1. Subdomain impersonation (VERY HIGH RISK)
        if canonical_domain and '.' in canonical_domain:
            canonical_base = canonical_domain.split('.')[0]
            if canonical_base in domain and canonical_domain not in domain:
                # Check if it's a subdomain impersonation like "sbi.co.in.phishing.com"
                if f"{canonical_domain}." in domain:
                    suspicious_indicators.append("CRITICAL: Subdomain impersonation detected")
                    risk_score += 0.8
                # Check for brand name in subdomain
                elif f"{canonical_base}." in domain or f".{canonical_base}." in domain:
                    suspicious_indicators.append("HIGH: Brand name in subdomain")
                    risk_score += 0.6
        
        # 2. Government domain impersonation (CRITICAL)
        if keyword.endswith('.gov') and '.gov' not in domain:
            if any(gov_indicator in domain for gov_indicator in ['gov', 'government', 'official']):
                suspicious_indicators.append("CRITICAL: Government domain impersonation")
                risk_score += 0.9
        
        # 3. Exact brand name in different TLD (HIGH RISK)
        if canonical_domain:
            canonical_base = canonical_domain.split('.')[0]
            domain_base = domain.split('.')[0]
            if canonical_base.lower() == domain_base.lower() and canonical_domain not in domain:
                suspicious_indicators.append("HIGH: Exact brand name with different TLD")
                risk_score += 0.7
        
        # 4. Banking/Financial service impersonation patterns
        banking_patterns = {
            'yono': ['yono', 'sbi'],
            'netbanking': ['net', 'banking', 'online'],
            'mobile banking': ['mobile', 'app', 'banking'],
            'digital banking': ['digital', 'online', 'banking']
        }
        
        for service, indicators in banking_patterns.items():
            if keyword in ['sbi', 'icicibank', 'hdfcbank'] and all(ind in domain.lower() for ind in indicators):
                suspicious_indicators.append(f"HIGH: {service.title()} service impersonation")
                risk_score += 0.6
        
        # ENHANCED CONTENT ANALYSIS
        
        title = content_info.get('title', '').lower()
        text_content = content_info.get('content', '').lower()
        
        # 5. Brand name prominence in title/content (CONTEXT-AWARE)
        if canonical_domain and (title or text_content):
            canonical_base = canonical_domain.split('.')[0].lower()
            brand_keywords = [canonical_base, keyword.lower()]
            
            # Analyze title relevance
            title_brand_score = 0
            if title:
                for brand_kw in brand_keywords:
                    if brand_kw in title:
                        # Check if it's actually relevant (not just coincidental)
                        title_words = title.split()
                        brand_context = any(
                            banking_word in title for banking_word in 
                            ['bank', 'banking', 'login', 'account', 'yono', 'netbanking', 'mobile banking']
                        )
                        if brand_context or len([w for w in title_words if brand_kw in w]) >= 2:
                            title_brand_score += 0.4
                            break
            
            # Analyze content relevance (only if title is also suspicious)
            content_brand_score = 0
            if title_brand_score > 0 and text_content:
                banking_context_words = [
                    'login', 'password', 'account', 'banking', 'verify', 'secure',
                    'netbanking', 'mobile banking', 'digital banking', 'yono'
                ]
                context_count = sum(1 for word in banking_context_words if word in text_content.lower())
                
                if context_count >= 3:  # Significant banking context
                    for brand_kw in brand_keywords:
                        content_mentions = text_content.lower().count(brand_kw)
                        if content_mentions >= 2:
                            content_brand_score += min(content_mentions * 0.1, 0.3)
                            break
            
            # Only flag if both title and content show brand impersonation
            total_brand_score = title_brand_score + content_brand_score
            if total_brand_score > 0.4 and canonical_domain not in domain:
                suspicious_indicators.append(f"HIGH: Brand impersonation in content (score: {total_brand_score:.2f})")
                risk_score += total_brand_score
        
        # 6. Phishing-specific language patterns (Enhanced)
        phishing_phrases = [
            'verify your account', 'account suspended', 'urgent action required',
            'click here to verify', 'update your information', 'confirm your identity',
            'account will be closed', 'temporary suspension', 'security alert',
            'immediate verification', 'account locked', 'suspicious activity detected',
            'verify now', 'act immediately', 'account deactivated'
        ]
        
        phishing_count = sum(1 for phrase in phishing_phrases if phrase in text_content)
        if phishing_count > 0:
            suspicious_indicators.append(f"HIGH: Phishing language detected ({phishing_count} phrases)")
            risk_score += min(phishing_count * 0.2, 0.6)
        
        # 7. Login form analysis (Enhanced)
        forms = content_info.get('forms', [])
        for form in forms:
            form_risk = 0
            if form.get('has_password') and form.get('has_email'):
                form_risk += 0.3
                
            # Check form action URL
            action = form.get('action_url', '')
            if action and canonical_domain and canonical_domain not in action:
                form_risk += 0.4
                suspicious_indicators.append("HIGH: Login form submits to external domain")
            
            if form_risk > 0.3:
                suspicious_indicators.append(f"MEDIUM: Suspicious login form detected")
                risk_score += form_risk
        
        # 8. URL structure analysis (Enhanced)
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.click', '.download', '.zip', '.top', '.xyz']
        if any(domain.endswith(tld) for tld in suspicious_tlds):
            suspicious_indicators.append("MEDIUM: Suspicious TLD")
            risk_score += 0.3
        
        # 9. Domain age and registration patterns (if available)
        if len(domain) > 30:
            suspicious_indicators.append("MEDIUM: Very long domain name")
            risk_score += 0.2
        
        # 10. Homograph/IDN attacks
        suspicious_chars = ['xn--', 'ο', 'а', 'е', 'о', 'р', 'с', 'у', 'х']  # Cyrillic lookalikes
        if any(char in domain for char in suspicious_chars):
            suspicious_indicators.append("HIGH: Potential homograph attack")
            risk_score += 0.6
        
        # ADVANCED PATTERN RECOGNITION
        
        # 11. Certificate/Security page impersonation
        security_keywords = ['certificate', 'ssl', 'security', 'verification', 'authenticate']
        if any(keyword in domain.lower() for keyword in security_keywords) and 'gov' in domain:
            suspicious_indicators.append("CRITICAL: Security service impersonation")
            risk_score += 0.8
        
        # 12. Mobile app impersonation
        mobile_keywords = ['app', 'mobile', 'download', 'install']
        if any(keyword in domain.lower() for keyword in mobile_keywords) and canonical_domain:
            canonical_base = canonical_domain.split('.')[0].lower()
            if canonical_base in domain.lower():
                suspicious_indicators.append("HIGH: Mobile app impersonation")
                risk_score += 0.6
        
        # 13. Urgent action indicators in domain
        urgent_keywords = ['urgent', 'immediate', 'now', 'today', 'expire']
        urgent_count = sum(1 for word in urgent_keywords if word in domain.lower())
        if urgent_count > 0:
            suspicious_indicators.append(f"MEDIUM: Urgent action keywords in domain ({urgent_count})")
            risk_score += urgent_count * 0.2
        
        # FINAL RISK CALCULATION
        
        # Normalize risk score to 0-1 range
        final_risk_score = min(risk_score, 1.0)
        
        # Boost score if multiple high-risk indicators
        high_risk_indicators = [ind for ind in suspicious_indicators if ind.startswith(('CRITICAL:', 'HIGH:'))]
        if len(high_risk_indicators) >= 2:
            final_risk_score = min(final_risk_score + 0.2, 1.0)
        
        return {
            'suspicious_indicators': suspicious_indicators,
            'risk_score': final_risk_score,
            'is_suspicious': final_risk_score >= 0.6,
            'high_risk_indicators': len(high_risk_indicators),
            'phishing_confidence': final_risk_score
        }
    
    def is_typosquatting(self, domain, canonical):
        """Enhanced typosquatting detection with specific phishing patterns"""
        domain_lower = domain.lower()
        canonical_lower = canonical.lower()
        
        # 1. Subdomain impersonation (most critical)
        if f"{canonical_lower}." in domain_lower and canonical_lower != domain_lower:
            return True
        
        # 2. Domain appending (like sbi.co.in.phishing.com)
        if canonical_lower in domain_lower and len(domain_lower) > len(canonical_lower) + 5:
            return True
        
        # 3. Character substitution patterns
        substitutions = {
            'o': ['0', 'ο'], 'i': ['1', 'l', 'ι'], 'a': ['@', 'α'], 
            'e': ['3', 'ε'], 'u': ['υ'], 'n': ['η'], 'm': ['μ'],
            's': ['5', '$'], 'g': ['9', 'q'], 'b': ['6'], 't': ['7']
        }
        
        domain_base = domain.split('.')[0].lower()
        canonical_base = canonical.split('.')[0].lower()
        
        for original, subs in substitutions.items():
            if original in canonical_base:
                for sub in subs:
                    if sub in domain_base and original not in domain_base:
                        return True
        
        # 4. Character insertion/deletion (edit distance = 1)
        if abs(len(domain_base) - len(canonical_base)) == 1:
            longer = domain_base if len(domain_base) > len(canonical_base) else canonical_base
            shorter = canonical_base if len(domain_base) > len(canonical_base) else domain_base
            
            for i in range(len(longer)):
                if longer[:i] + longer[i+1:] == shorter:
                    return True
        
        # 5. Homograph attacks (similar looking characters)
        homographs = {
            'a': ['а', 'α'], 'e': ['е', 'ε'], 'o': ['о', 'ο'], 
            'p': ['р', 'ρ'], 'c': ['с'], 'x': ['х'], 'y': ['у']
        }
        
        for original, lookalikes in homographs.items():
            if original in canonical_base:
                for lookalike in lookalikes:
                    if lookalike in domain_base:
                        return True
        
        return False
    
    def detect_specific_phishing_patterns(self, domain, keyword, content_info):
        """Detect specific phishing patterns with context awareness"""
        high_risk_patterns = []
        risk_boost = 0.0
        
        domain_lower = domain.lower()
        canonical_domain = self.brand_map.get(keyword, '').replace('https://', '').replace('www.', '')
        title = content_info.get('title', '').lower()
        text_content = content_info.get('content', '').lower()
        
        # 1. Government certificate impersonation (dc.crsorgi.gov.in.viewcertificates.xyz)
        if 'gov.in' in domain_lower and '.gov.in' not in domain_lower:
            # Check if content is actually government-related
            gov_context = any(word in text_content for word in [
                'government', 'certificate', 'official', 'ministry', 'department'
            ]) if text_content else True
            
            if gov_context:
                high_risk_patterns.append("CRITICAL: Government domain impersonation with subdomain")
                risk_boost += 0.9
        
        # 2. YONO SBI impersonation patterns (only if content is banking-related)
        yono_patterns = [
            'yono-sbi', 'yonosbi', 'sbi-yono', 'sbiyono', 
            'yono.sbi', 'sbi.yono', 'yonobusiness'
        ]
        
        banking_context = any(word in (title + ' ' + text_content) for word in [
            'bank', 'banking', 'account', 'login', 'yono', 'sbi'
        ]) if (title or text_content) else False
        
        for pattern in yono_patterns:
            if pattern in domain_lower and 'sbi.co.in' not in domain_lower and banking_context:
                high_risk_patterns.append(f"CRITICAL: YONO SBI service impersonation ({pattern})")
                risk_boost += 0.8
                break
        
        # 3. Banking app/service specific patterns (context-aware)
        if banking_context and canonical_domain and canonical_domain not in domain_lower:
            banking_services = {
                'netbanking': ['netbanking', 'net-banking', 'onlinebanking'],
                'mobilebanking': ['mobilebanking', 'mobile-banking', 'bankingapp'],
                'digitalbanking': ['digitalbanking', 'digital-banking', 'ebanking']
            }
            
            for service, patterns in banking_services.items():
                for pattern in patterns:
                    if pattern in domain_lower:
                        high_risk_patterns.append(f"HIGH: {service.title()} impersonation")
                        risk_boost += 0.6
                        break
        
        # 4. Certificate/Security service impersonation (context-aware)
        security_patterns = ['certificate', 'ssl', 'security', 'verification', 'viewcertificate']
        security_context = any(word in (title + ' ' + text_content) for word in [
            'certificate', 'security', 'verification', 'ssl', 'authenticate'
        ]) if (title or text_content) else True
        
        for pattern in security_patterns:
            if pattern in domain_lower and ('gov' in keyword or 'official' in domain_lower) and security_context:
                high_risk_patterns.append(f"CRITICAL: Security service impersonation ({pattern})")
                risk_boost += 0.8
                break
        
        # 5. Brand impersonation in content (not just domain)
        if canonical_domain and (title or text_content):
            brand_name = canonical_domain.split('.')[0]
            
            # Check title relevance
            title_suspicious = False
            if title and brand_name in title:
                # Must have banking context in title to be suspicious
                title_banking_words = ['bank', 'banking', 'login', 'account', 'yono', 'online']
                if any(word in title for word in title_banking_words):
                    title_suspicious = True
            
            # Check content relevance (only if title is also suspicious)
            content_suspicious = False
            if title_suspicious and text_content and brand_name in text_content:
                # Count banking-related context
                banking_context_count = sum(1 for word in [
                    'login', 'password', 'account', 'banking', 'verify', 'secure',
                    'netbanking', 'mobile banking', 'digital banking'
                ] if word in text_content)
                
                if banking_context_count >= 3:
                    content_suspicious = True
            
            # Only flag if both title and content show clear impersonation
            if title_suspicious and content_suspicious and canonical_domain not in domain_lower:
                high_risk_patterns.append(f"HIGH: Brand impersonation in title and content")
                risk_boost += 0.6
        
        return high_risk_patterns, min(risk_boost, 1.0)
    
    def analyze_domain(self, domain, keyword):
        """Complete analysis of a domain"""
        print(f"\nAnalyzing: {domain} (keyword: {keyword})")
        
        # Get page content
        content_info = self.get_page_content(domain)
        
        if content_info.get('error'):
            return {
                'domain': domain,
                'keyword': keyword,
                'status': 'ERROR',
                'error': content_info['error'],
                'risk_score': 0.5  # Unknown risk
            }
        
        # Get legitimate site content for comparison
        canonical_url = self.brand_map.get(keyword)
        legitimate_content = None
        if canonical_url:
            legitimate_content = self.get_page_content(canonical_url)
        
        # Take screenshots
        screenshot = self.take_screenshot(domain)
        legitimate_screenshot = None
        if canonical_url:
            legitimate_screenshot = self.take_screenshot(canonical_url)
        
        # Analyze similarities
        content_similarity = 0
        visual_similarity = 0
        
        if legitimate_content and not legitimate_content.get('error'):
            content_similarity = self.analyze_content_similarity(
                content_info.get('content', ''),
                legitimate_content.get('content', '')
            )
        
        if screenshot and legitimate_screenshot:
            visual_similarity = self.compare_visual_similarity(screenshot, legitimate_screenshot)
        
        # Enhanced analysis with specific pattern detection
        domain_analysis = {
            'domain': domain,
            'keyword': keyword,
            'content_info': content_info
        }
        
        # Run specific phishing pattern detection
        specific_patterns, pattern_risk = self.detect_specific_phishing_patterns(domain, keyword, content_info)
        
        # Run LLM-style analysis
        llm_result = self.llm_phishing_analysis(domain_analysis, legitimate_content)
        
        # Combine specific patterns with LLM indicators
        all_indicators = llm_result.get('suspicious_indicators', []) + specific_patterns
        llm_result['suspicious_indicators'] = all_indicators
        llm_result['risk_score'] = min(llm_result['risk_score'] + pattern_risk, 1.0)
        
        # Context-aware risk score calculation
        llm_score = llm_result['risk_score']
        
        # Content similarity analysis (high similarity to legitimate site reduces risk)
        if content_similarity is not None and content_similarity > 0.3:
            # High content similarity to legitimate site - likely not phishing
            content_factor = max(0, 1 - (content_similarity * 2))  # Strong penalty for high similarity
        else:
            # Low or no similarity - neutral to suspicious
            content_factor = 0.3
        
        # Visual similarity (less important than content)
        visual_factor = (1 - visual_similarity) * 0.1 if visual_similarity else 0.1
        
        # Base calculation with content-aware weighting
        final_risk_score = (
            llm_score * 0.6 +  # LLM analysis (main factor)
            content_factor * 0.3 +  # Content similarity factor
            visual_factor * 0.1   # Visual factor (minimal weight)
        )
        
        # Boost for critical patterns
        critical_indicators = [ind for ind in llm_result.get('suspicious_indicators', []) if 'CRITICAL:' in ind]
        if critical_indicators:
            final_risk_score = min(final_risk_score + 0.3, 1.0)
        
        # Reduce score if content is highly similar to legitimate site
        if content_similarity and content_similarity > 0.5:
            final_risk_score = max(final_risk_score - 0.2, 0.0)
        
        # Special handling for domains with brand names but no relevant content
        canonical_domain = self.brand_map.get(keyword, '').replace('https://', '').replace('www.', '')
        if canonical_domain:
            brand_name = canonical_domain.split('.')[0].lower()
            title = content_info.get('title', '').lower()
            text_content = content_info.get('content', '').lower()
            
            # If domain has brand name but content is completely unrelated
            if (brand_name in domain.lower() and 
                canonical_domain not in domain.lower() and
                title and text_content):
                
                # Check if content is actually related to the brand
                brand_related_words = [
                    'bank', 'banking', 'account', 'login', 'yono', 'netbanking',
                    'government', 'official', 'certificate', 'verification'
                ]
                
                content_relevance = sum(1 for word in brand_related_words 
                                      if word in (title + ' ' + text_content))
                
                # If no brand-related content, reduce suspicion significantly
                if content_relevance == 0:
                    final_risk_score = max(final_risk_score - 0.4, 0.1)
        
        # Lower threshold for better detection of sophisticated phishing
        is_phishing = final_risk_score > 0.5  # Lowered from 0.6 to 0.5
        
        # Override for critical indicators
        critical_indicators = [ind for ind in llm_result.get('suspicious_indicators', []) if 'CRITICAL:' in ind]
        if critical_indicators:
            is_phishing = True
            final_risk_score = max(final_risk_score, 0.8)
        
        return {
            'domain': domain,
            'keyword': keyword,
            'status': 'ANALYZED',
            'content_similarity': round(content_similarity, 3),
            'visual_similarity': round(visual_similarity, 3),
            'llm_indicators': llm_result['suspicious_indicators'],
            'risk_score': round(final_risk_score, 3),
            'is_phishing': is_phishing,
            'confidence': round(llm_result.get('phishing_confidence', final_risk_score), 3),
            'title': content_info.get('title', ''),
            'has_forms': bool(content_info.get('forms')),
            'financial_keywords': content_info.get('keywords', [])
        }
    
    def process_candidates(self, filename, limit=None):
        """Process candidate domains"""
        results = []
        
        with open(filename, 'r') as f:
            reader = csv.DictReader(f)
            candidates = list(reader)
        
        total_to_process = len(candidates) if limit is None else min(limit, len(candidates))
        print(f"Processing {total_to_process} candidates...")
        
        candidates_to_process = candidates if limit is None else candidates[:limit]
        for i, row in enumerate(candidates_to_process):
            if i > 0 and i % 10 == 0:
                print(f"Processed {i}/{total_to_process} domains...")
                time.sleep(2)  # Rate limiting
            
            domain = row['Domains'].strip()
            keyword = row['Keyword Found'].strip()
            
            result = self.analyze_domain(domain, keyword)
            result.update({
                'detection_method': row['Detected by'],
                'monitoring_date': row['Monitoring Date']
            })
            
            results.append(result)
        
        return results
    
    def save_results(self, results, filename='phishing_analysis_results.csv'):
        """Save analysis results"""
        if not results:
            return
            
        fieldnames = [
            'domain', 'keyword', 'status', 'risk_score', 'is_phishing', 'confidence',
            'content_similarity', 'visual_similarity', 'llm_indicators',
            'title', 'has_forms', 'financial_keywords',
            'detection_method', 'monitoring_date', 'error'
        ]
        
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            
            for result in results:
                # Convert lists to strings for CSV
                result['llm_indicators'] = '; '.join(result.get('llm_indicators', []))
                result['financial_keywords'] = '; '.join(result.get('financial_keywords', []))
                writer.writerow(result)
        
        print(f"Results saved to {filename}")
    
    def cleanup(self):
        """Cleanup resources"""
        if self.driver:
            self.driver.quit()

def main():
    detector = PhishingDetector()
    
    try:
        # Process all candidates with enhanced detection
        results = detector.process_candidates('candidates.csv', limit=None)
        
        # Save results
        detector.save_results(results)
        
        # Print summary
        phishing_count = sum(1 for r in results if r.get('is_phishing'))
        high_risk_count = sum(1 for r in results if r.get('risk_score', 0) > 0.7)
        
        print(f"\n=== ANALYSIS SUMMARY ===")
        print(f"Total analyzed: {len(results)}")
        print(f"Identified as phishing: {phishing_count}")
        print(f"High risk (>0.7): {high_risk_count}")
        
        # Show top risks
        sorted_results = sorted(results, key=lambda x: x.get('risk_score', 0), reverse=True)
        print(f"\nTop 5 highest risk domains:")
        for i, result in enumerate(sorted_results[:5]):
            print(f"{i+1}. {result['domain']} - Risk: {result['risk_score']} - "
                  f"Indicators: {result.get('llm_indicators', 'None')}")
    
    finally:
        detector.cleanup()

if __name__ == "__main__":
    main()