---
inclusion: always
---

# Phishing Detection System Standards

## Overview
This document defines the standards, best practices, and guidelines for developing and maintaining the phishing detection system that analyzes candidate domains to identify legitimate phishing threats while minimizing false positives.

## Core Principles

### 1. Multi-Layer Detection Approach
- **Domain Analysis**: Typosquatting, suspicious TLDs, domain structure
- **Content Analysis**: HTML/text similarity, phishing patterns, form analysis
- **Visual Analysis**: Screenshot comparison when feasible
- **Behavioral Analysis**: SSL certificates, redirects, security headers

### 2. Risk-Based Scoring
- Use normalized risk scores (0.0 to 1.0) for consistent evaluation
- Combine multiple detection methods with weighted scoring
- Threshold of 0.6+ indicates likely phishing
- Provide detailed reasoning for each assessment

### 3. Performance Requirements
- Process domains efficiently with rate limiting (1-2 seconds between requests)
- Handle network timeouts and SSL errors gracefully
- Support batch processing of candidate lists
- Maintain detailed logs for audit trails

## Technical Standards

### Code Structure
```python
class PhishingDetector:
    def __init__(self):
        # Load configuration and initialize components
        
    def analyze_domain(self, domain, keyword):
        # Main analysis method returning standardized results
        
    def calculate_risk_score(self, indicators):
        # Weighted risk calculation
        
    def save_results(self, results, filename):
        # Standardized output format
```

### Data Formats

#### Input Format (CSV)
```csv
Domains,Keyword Found,Monitoring Date,Detected by
example.com,sbi,2025-10-11,Similarity Jaro-Winkler
```

#### Output Format (CSV)
```csv
domain,keyword,final_risk_score,is_phishing,domain_reasons,content_reasons,title,status_code,detection_method,monitoring_date
```

### Risk Scoring Weights
- Domain Analysis: 20%
- Content Analysis: 50% 
- Similarity Analysis: 30%

### Detection Thresholds
- **Low Risk**: 0.0 - 0.3 (Likely legitimate)
- **Medium Risk**: 0.3 - 0.6 (Requires review)
- **High Risk**: 0.6 - 1.0 (Likely phishing)

## Security Considerations

### Safe Analysis Practices
- Use headless browsers with sandboxing
- Implement request timeouts (15 seconds max)
- Disable JavaScript execution when possible
- Use VPN or isolated network for analysis
- Never submit forms or interact with suspicious sites

### Data Protection
- Sanitize all output data
- Remove sensitive information from logs
- Encrypt stored analysis results
- Implement secure API endpoints if exposing functionality

## Brand Mapping Standards

### Brand Map Format
```csv
keyword,canonical_url
sbi,https://sbi.co.in
icicibank,https://www.icicibank.com
```

### Canonical Domain Rules
- Use primary domain without www prefix for comparison
- Include all official subdomains in whitelist
- Regular updates from official brand sources
- Version control for brand map changes

## Detection Patterns

### Typosquatting Indicators
- Character substitution (o→0, i→1, l→1)
- Character insertion/deletion (edit distance = 1)
- Homograph attacks (unicode lookalikes)
- Subdomain abuse

### Content Indicators
- Urgent language: "urgent", "expire", "suspend", "verify now"
- Financial keywords: "login", "password", "account", "verify"
- Suspicious forms: password + email fields with external action
- Missing security headers: HSTS, CSP

### Visual Indicators
- Logo similarity analysis
- Color scheme matching
- Layout structure comparison
- Font and styling analysis

## Error Handling Standards

### Network Errors
```python
try:
    response = requests.get(url, timeout=15)
except requests.exceptions.SSLError:
    return {'error': 'SSL Certificate Error', 'ssl_issue': True}
except requests.exceptions.Timeout:
    return {'error': 'Timeout', 'status_code': 0}
```

### Graceful Degradation
- Continue analysis even if some components fail
- Provide partial results with confidence indicators
- Log all errors for debugging
- Implement retry logic for transient failures

## Testing Requirements

### Unit Tests
- Test each detection method independently
- Mock external dependencies (requests, selenium)
- Validate risk score calculations
- Test edge cases and error conditions

### Integration Tests
- End-to-end analysis workflows
- Brand map loading and validation
- Output format verification
- Performance benchmarks

### Test Data
- Known phishing domains (with permission)
- Legitimate domains from brand map
- Edge cases: IDN domains, long URLs, redirects
- Historical false positives for regression testing

## Monitoring and Alerting

### Key Metrics
- Analysis success rate
- Average processing time per domain
- False positive/negative rates
- System resource utilization

### Alerting Thresholds
- Analysis failure rate > 10%
- Average processing time > 30 seconds
- Memory usage > 80%
- Disk space < 1GB

## Documentation Standards

### Code Documentation
- Docstrings for all public methods
- Inline comments for complex logic
- Type hints for function parameters
- Examples in docstrings

### Analysis Reports
- Executive summary with key findings
- Detailed methodology explanation
- Risk assessment breakdown
- Recommendations for action

## Compliance and Legal

### Data Handling
- Comply with GDPR/privacy regulations
- Obtain proper authorization for domain analysis
- Respect robots.txt and rate limiting
- Document data retention policies

### Ethical Considerations
- Use analysis results responsibly
- Avoid disrupting legitimate services
- Report findings through proper channels
- Maintain confidentiality of analysis methods

## Version Control and Deployment

### Code Management
- Feature branches for new detection methods
- Code review requirements for all changes
- Automated testing in CI/CD pipeline
- Semantic versioning for releases

### Configuration Management
- Environment-specific configurations
- Secure storage of API keys and credentials
- Automated deployment scripts
- Rollback procedures for failed deployments

## Performance Optimization

### Caching Strategies
- Cache legitimate domain analysis results
- Store brand map in memory for fast lookup
- Implement result caching with TTL
- Use connection pooling for HTTP requests

### Scalability Considerations
- Horizontal scaling for batch processing
- Queue-based architecture for high volume
- Database optimization for result storage
- Load balancing for API endpoints