---
inclusion: always
---

# Security and Compliance Guidelines for Phishing Detection

## Overview
This document establishes security protocols, compliance requirements, and ethical guidelines for the phishing detection system to ensure safe, legal, and responsible operation.

## Security Architecture

### 1. Network Security
```python
# Secure HTTP client configuration
SECURE_REQUEST_CONFIG = {
    'timeout': 15,
    'verify': False,  # SSL verification disabled for analysis
    'allow_redirects': True,
    'max_redirects': 5,
    'headers': {
        'User-Agent': 'Mozilla/5.0 (Security Research Bot)',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'close'
    }
}
```

### 2. Sandboxed Analysis Environment
```python
class SecureAnalyzer:
    def __init__(self):
        self.setup_sandbox()
    
    def setup_sandbox(self):
        """Configure secure analysis environment"""
        # Use isolated network namespace
        # Disable JavaScript execution
        # Implement request filtering
        # Set up VPN/proxy routing
        pass
    
    def analyze_safely(self, domain):
        """Perform analysis in sandboxed environment"""
        with self.sandbox_context():
            return self.perform_analysis(domain)
```

### 3. Data Sanitization
```python
def sanitize_output_data(analysis_result):
    """Remove sensitive information from analysis results"""
    
    # Remove potential PII from content
    sanitized = analysis_result.copy()
    
    # Sanitize HTML content
    if 'content' in sanitized:
        sanitized['content'] = sanitize_html_content(sanitized['content'])
    
    # Remove sensitive headers
    if 'headers' in sanitized:
        sensitive_headers = ['set-cookie', 'authorization', 'x-api-key']
        sanitized['headers'] = {
            k: v for k, v in sanitized['headers'].items() 
            if k.lower() not in sensitive_headers
        }
    
    # Truncate long text fields
    if 'text_content' in sanitized and len(sanitized['text_content']) > 1000:
        sanitized['text_content'] = sanitized['text_content'][:1000] + '...'
    
    return sanitized

def sanitize_html_content(html):
    """Remove potentially sensitive content from HTML"""
    import re
    
    # Remove email addresses
    html = re.sub(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', '[EMAIL]', html)
    
    # Remove phone numbers
    html = re.sub(r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b', '[PHONE]', html)
    
    # Remove potential API keys or tokens
    html = re.sub(r'\b[A-Za-z0-9]{32,}\b', '[TOKEN]', html)
    
    return html
```

## Access Control and Authentication

### 1. API Security
```python
from functools import wraps
import jwt
import hashlib

def require_api_key(f):
    """Decorator to require valid API key"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        if not api_key or not validate_api_key(api_key):
            return {'error': 'Invalid API key'}, 401
        return f(*args, **kwargs)
    return decorated_function

def validate_api_key(api_key):
    """Validate API key against stored hashes"""
    api_key_hash = hashlib.sha256(api_key.encode()).hexdigest()
    return api_key_hash in VALID_API_KEY_HASHES

def rate_limit_by_key(max_requests=100, window_minutes=60):
    """Rate limiting decorator"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        if is_rate_limited(api_key, max_requests, window_minutes):
            return {'error': 'Rate limit exceeded'}, 429
        return f(*args, **kwargs)
    return decorated_function
```

### 2. Audit Logging
```python
import logging
from datetime import datetime

class SecurityAuditLogger:
    def __init__(self):
        self.logger = logging.getLogger('security_audit')
        self.setup_secure_logging()
    
    def setup_secure_logging(self):
        """Configure secure audit logging"""
        handler = logging.FileHandler('/var/log/phishing-detector/audit.log')
        formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.INFO)
    
    def log_analysis_request(self, domain, user_id, api_key_hash):
        """Log analysis request for audit trail"""
        self.logger.info(f"ANALYSIS_REQUEST: domain={domain}, user={user_id}, "
                        f"api_key_hash={api_key_hash[:8]}..., "
                        f"timestamp={datetime.utcnow().isoformat()}")
    
    def log_security_event(self, event_type, details):
        """Log security-related events"""
        self.logger.warning(f"SECURITY_EVENT: type={event_type}, "
                           f"details={details}, "
                           f"timestamp={datetime.utcnow().isoformat()}")
```

## Compliance Requirements

### 1. Data Protection (GDPR/Privacy)
```python
class DataProtectionCompliance:
    def __init__(self):
        self.data_retention_days = 90
        self.anonymization_required = True
    
    def process_personal_data(self, data):
        """Process data in compliance with privacy regulations"""
        
        # Check for personal data
        if self.contains_personal_data(data):
            if not self.has_consent():
                raise ComplianceError("No consent for personal data processing")
            
            # Anonymize personal data
            data = self.anonymize_data(data)
        
        # Set retention policy
        data['retention_until'] = self.calculate_retention_date()
        
        return data
    
    def contains_personal_data(self, data):
        """Check if data contains personal information"""
        personal_patterns = [
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # Email
            r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',  # Phone
            r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b'  # Credit card
        ]
        
        content = str(data)
        for pattern in personal_patterns:
            if re.search(pattern, content):
                return True
        return False
    
    def anonymize_data(self, data):
        """Anonymize personal data"""
        # Replace with placeholders
        data = re.sub(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', 
                     '[EMAIL_REDACTED]', str(data))
        return data
```

### 2. Legal Authorization
```python
class LegalComplianceChecker:
    def __init__(self):
        self.authorized_domains = self.load_authorized_domains()
        self.terms_of_service_accepted = False
    
    def check_analysis_authorization(self, domain):
        """Verify legal authorization to analyze domain"""
        
        # Check if domain is in authorized list
        if domain in self.authorized_domains:
            return True
        
        # Check if domain is publicly accessible
        if self.is_publicly_accessible(domain):
            return True
        
        # Check robots.txt compliance
        if not self.check_robots_txt_compliance(domain):
            raise ComplianceError(f"Robots.txt disallows analysis of {domain}")
        
        return True
    
    def check_robots_txt_compliance(self, domain):
        """Check robots.txt for analysis permissions"""
        try:
            robots_url = f"https://{domain}/robots.txt"
            response = requests.get(robots_url, timeout=5)
            
            if response.status_code == 200:
                # Parse robots.txt for restrictions
                return self.parse_robots_txt(response.text)
            
            return True  # No robots.txt means no restrictions
        except:
            return True  # Assume allowed if can't check
    
    def parse_robots_txt(self, robots_content):
        """Parse robots.txt content for restrictions"""
        lines = robots_content.split('\n')
        user_agent_applies = False
        
        for line in lines:
            line = line.strip().lower()
            
            if line.startswith('user-agent:'):
                agent = line.split(':', 1)[1].strip()
                user_agent_applies = (agent == '*' or 'bot' in agent)
            
            elif user_agent_applies and line.startswith('disallow:'):
                path = line.split(':', 1)[1].strip()
                if path == '/' or path == '':
                    return False  # Disallows all access
        
        return True
```

## Ethical Guidelines

### 1. Responsible Disclosure
```python
class ResponsibleDisclosure:
    def __init__(self):
        self.disclosure_channels = {
            'cert_teams': ['cert@domain.com', 'security@domain.com'],
            'abuse_contacts': ['abuse@domain.com'],
            'law_enforcement': ['ic3.gov', 'cert.org']
        }
    
    def report_phishing_site(self, analysis_result):
        """Report confirmed phishing site through proper channels"""
        
        if analysis_result['is_phishing'] and analysis_result['confidence'] > 0.8:
            
            # Prepare disclosure report
            report = self.prepare_disclosure_report(analysis_result)
            
            # Send to appropriate authorities
            self.send_to_cert_teams(report)
            self.send_to_hosting_provider(report)
            
            # Log disclosure action
            self.log_disclosure_action(analysis_result['domain'], report)
    
    def prepare_disclosure_report(self, analysis_result):
        """Prepare standardized disclosure report"""
        return {
            'domain': analysis_result['domain'],
            'detected_date': datetime.utcnow().isoformat(),
            'confidence_score': analysis_result['confidence'],
            'evidence': analysis_result['evidence_summary'],
            'target_brand': analysis_result['target_brand'],
            'reporter_contact': 'security@yourorganization.com'
        }
```

### 2. Harm Minimization
```python
class HarmMinimization:
    def __init__(self):
        self.interaction_limits = {
            'max_requests_per_domain': 3,
            'request_interval_seconds': 5,
            'max_concurrent_analyses': 10
        }
    
    def analyze_with_minimal_impact(self, domain):
        """Perform analysis while minimizing impact on target"""
        
        # Check if domain has been analyzed recently
        if self.recently_analyzed(domain):
            return self.get_cached_result(domain)
        
        # Implement rate limiting
        self.enforce_rate_limits(domain)
        
        # Use minimal resource consumption
        analysis_config = {
            'timeout': 10,  # Shorter timeout
            'max_content_size': 1024 * 1024,  # 1MB limit
            'disable_images': True,
            'disable_javascript': True
        }
        
        return self.perform_lightweight_analysis(domain, analysis_config)
    
    def enforce_rate_limits(self, domain):
        """Enforce rate limiting to prevent overloading target"""
        last_request = self.get_last_request_time(domain)
        
        if last_request:
            time_since_last = time.time() - last_request
            if time_since_last < self.interaction_limits['request_interval_seconds']:
                sleep_time = self.interaction_limits['request_interval_seconds'] - time_since_last
                time.sleep(sleep_time)
        
        self.record_request_time(domain)
```

## Incident Response

### 1. Security Incident Handling
```python
class SecurityIncidentHandler:
    def __init__(self):
        self.incident_severity_levels = {
            'LOW': 1,
            'MEDIUM': 2,
            'HIGH': 3,
            'CRITICAL': 4
        }
    
    def handle_security_incident(self, incident_type, details):
        """Handle security incidents according to severity"""
        
        severity = self.assess_incident_severity(incident_type, details)
        
        # Immediate response actions
        if severity >= self.incident_severity_levels['HIGH']:
            self.initiate_emergency_response(incident_type, details)
        
        # Log incident
        self.log_security_incident(incident_type, details, severity)
        
        # Notify stakeholders
        self.notify_stakeholders(incident_type, severity)
        
        # Begin investigation
        self.start_incident_investigation(incident_type, details)
    
    def assess_incident_severity(self, incident_type, details):
        """Assess severity of security incident"""
        severity_mapping = {
            'data_breach': 'CRITICAL',
            'unauthorized_access': 'HIGH',
            'ddos_attack': 'MEDIUM',
            'suspicious_activity': 'LOW'
        }
        
        return self.incident_severity_levels.get(
            severity_mapping.get(incident_type, 'MEDIUM'),
            2
        )
```

### 2. Data Breach Response
```python
class DataBreachResponse:
    def __init__(self):
        self.notification_requirements = {
            'gdpr_notification_hours': 72,
            'user_notification_required': True,
            'regulatory_bodies': ['data_protection_authority']
        }
    
    def handle_data_breach(self, breach_details):
        """Handle data breach according to legal requirements"""
        
        # Immediate containment
        self.contain_breach(breach_details)
        
        # Assess impact
        impact_assessment = self.assess_breach_impact(breach_details)
        
        # Legal notifications
        if impact_assessment['requires_notification']:
            self.send_regulatory_notifications(breach_details, impact_assessment)
            self.notify_affected_users(breach_details, impact_assessment)
        
        # Remediation
        self.implement_remediation_measures(breach_details)
        
        # Documentation
        self.document_breach_response(breach_details, impact_assessment)
```

## Monitoring and Alerting

### 1. Security Monitoring
```python
class SecurityMonitor:
    def __init__(self):
        self.alert_thresholds = {
            'failed_auth_attempts': 5,
            'unusual_traffic_volume': 1000,
            'error_rate_threshold': 0.1,
            'response_time_threshold': 30
        }
    
    def monitor_security_metrics(self):
        """Continuously monitor security-related metrics"""
        
        metrics = self.collect_security_metrics()
        
        # Check for anomalies
        for metric, value in metrics.items():
            if self.is_anomalous(metric, value):
                self.trigger_security_alert(metric, value)
    
    def trigger_security_alert(self, metric, value):
        """Trigger security alert for anomalous activity"""
        alert = {
            'timestamp': datetime.utcnow().isoformat(),
            'metric': metric,
            'value': value,
            'threshold': self.alert_thresholds.get(metric),
            'severity': self.calculate_alert_severity(metric, value)
        }
        
        self.send_alert(alert)
        self.log_security_alert(alert)
```

### 2. Compliance Monitoring
```python
class ComplianceMonitor:
    def __init__(self):
        self.compliance_checks = [
            'data_retention_policy',
            'access_control_validation',
            'audit_log_integrity',
            'encryption_compliance'
        ]
    
    def run_compliance_audit(self):
        """Run comprehensive compliance audit"""
        
        audit_results = {}
        
        for check in self.compliance_checks:
            try:
                result = getattr(self, f'check_{check}')()
                audit_results[check] = {
                    'status': 'PASS' if result else 'FAIL',
                    'details': result
                }
            except Exception as e:
                audit_results[check] = {
                    'status': 'ERROR',
                    'error': str(e)
                }
        
        # Generate compliance report
        self.generate_compliance_report(audit_results)
        
        return audit_results
```