---
inclusion: fileMatch
fileMatchPattern: '*api*'
---

# API Integration Patterns for Phishing Detection System

## Overview
This document defines API design patterns, integration standards, and service architecture for the phishing detection system, enabling seamless integration with external systems and scalable deployment.

## RESTful API Design

### 1. Core API Endpoints
```python
from flask import Flask, request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["100 per hour"]
)

# Single domain analysis
@app.route('/api/v1/analyze', methods=['POST'])
@limiter.limit("10 per minute")
@require_api_key
def analyze_domain():
    """
    Analyze a single domain for phishing indicators
    
    Request Body:
    {
        "domain": "example.com",
        "keyword": "sbi",
        "options": {
            "include_screenshot": false,
            "deep_analysis": true,
            "timeout": 15
        }
    }
    
    Response:
    {
        "domain": "example.com",
        "keyword": "sbi",
        "risk_score": 0.85,
        "is_phishing": true,
        "confidence": 0.92,
        "analysis_timestamp": "2025-10-17T10:30:00Z",
        "indicators": [...],
        "evidence": {...}
    }
    """
    try:
        data = request.get_json()
        
        # Validate input
        validate_analysis_request(data)
        
        # Perform analysis
        result = phishing_detector.analyze_domain(
            domain=data['domain'],
            keyword=data['keyword'],
            options=data.get('options', {})
        )
        
        return jsonify(result), 200
        
    except ValidationError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        return jsonify({'error': 'Internal server error'}), 500

# Batch analysis
@app.route('/api/v1/analyze/batch', methods=['POST'])
@limiter.limit("5 per minute")
@require_api_key
def analyze_batch():
    """
    Analyze multiple domains in batch
    
    Request Body:
    {
        "domains": [
            {"domain": "example1.com", "keyword": "sbi"},
            {"domain": "example2.com", "keyword": "icici"}
        ],
        "options": {
            "parallel_processing": true,
            "max_concurrent": 5
        }
    }
    """
    try:
        data = request.get_json()
        
        # Validate batch size
        if len(data['domains']) > 100:
            return jsonify({'error': 'Batch size exceeds limit (100)'}), 400
        
        # Process batch
        results = phishing_detector.analyze_batch(
            domains=data['domains'],
            options=data.get('options', {})
        )
        
        return jsonify({
            'batch_id': generate_batch_id(),
            'total_domains': len(data['domains']),
            'results': results,
            'processing_time': calculate_processing_time()
        }), 200
        
    except Exception as e:
        logger.error(f"Batch analysis failed: {e}")
        return jsonify({'error': 'Internal server error'}), 500

# Analysis status
@app.route('/api/v1/analyze/status/<batch_id>', methods=['GET'])
@require_api_key
def get_analysis_status(batch_id):
    """Get status of batch analysis"""
    try:
        status = batch_processor.get_status(batch_id)
        return jsonify(status), 200
    except BatchNotFoundError:
        return jsonify({'error': 'Batch not found'}), 404
```

### 2. Webhook Integration
```python
@app.route('/api/v1/webhooks/analysis-complete', methods=['POST'])
@require_webhook_signature
def analysis_complete_webhook():
    """
    Webhook endpoint for analysis completion notifications
    
    Payload:
    {
        "event": "analysis.completed",
        "batch_id": "batch_123",
        "timestamp": "2025-10-17T10:30:00Z",
        "results_summary": {
            "total_analyzed": 50,
            "phishing_detected": 5,
            "high_risk_count": 8
        },
        "callback_url": "https://client.com/api/results"
    }
    """
    try:
        payload = request.get_json()
        
        # Process webhook
        webhook_processor.handle_analysis_complete(payload)
        
        return jsonify({'status': 'received'}), 200
        
    except Exception as e:
        logger.error(f"Webhook processing failed: {e}")
        return jsonify({'error': 'Webhook processing failed'}), 500

def require_webhook_signature(f):
    """Validate webhook signature"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        signature = request.headers.get('X-Webhook-Signature')
        if not validate_webhook_signature(request.data, signature):
            return jsonify({'error': 'Invalid signature'}), 401
        return f(*args, **kwargs)
    return decorated_function
```

## Asynchronous Processing

### 1. Task Queue Integration
```python
from celery import Celery
from celery.result import AsyncResult

# Celery configuration
celery_app = Celery('phishing_detector')
celery_app.config_from_object('celeryconfig')

@celery_app.task(bind=True, max_retries=3)
def analyze_domain_async(self, domain, keyword, options=None):
    """Asynchronous domain analysis task"""
    try:
        result = phishing_detector.analyze_domain(domain, keyword, options)
        
        # Store result in database
        store_analysis_result(result)
        
        # Send webhook notification if configured
        if options and options.get('webhook_url'):
            send_webhook_notification(options['webhook_url'], result)
        
        return result
        
    except Exception as e:
        logger.error(f"Async analysis failed for {domain}: {e}")
        
        # Retry with exponential backoff
        if self.request.retries < self.max_retries:
            raise self.retry(countdown=60 * (2 ** self.request.retries))
        
        # Max retries reached, mark as failed
        return {'error': str(e), 'status': 'failed'}

@app.route('/api/v1/analyze/async', methods=['POST'])
@require_api_key
def analyze_domain_async_endpoint():
    """Submit domain for asynchronous analysis"""
    try:
        data = request.get_json()
        
        # Submit task to queue
        task = analyze_domain_async.delay(
            domain=data['domain'],
            keyword=data['keyword'],
            options=data.get('options', {})
        )
        
        return jsonify({
            'task_id': task.id,
            'status': 'submitted',
            'estimated_completion': calculate_eta()
        }), 202
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/v1/analyze/async/<task_id>', methods=['GET'])
@require_api_key
def get_async_result(task_id):
    """Get result of asynchronous analysis"""
    try:
        result = AsyncResult(task_id, app=celery_app)
        
        if result.ready():
            return jsonify({
                'task_id': task_id,
                'status': 'completed',
                'result': result.result
            }), 200
        else:
            return jsonify({
                'task_id': task_id,
                'status': 'pending',
                'progress': result.info.get('progress', 0) if result.info else 0
            }), 200
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500
```

### 2. Real-time Updates with WebSockets
```python
from flask_socketio import SocketIO, emit, join_room, leave_room

socketio = SocketIO(app, cors_allowed_origins="*")

@socketio.on('subscribe_analysis')
def handle_analysis_subscription(data):
    """Subscribe to real-time analysis updates"""
    task_id = data['task_id']
    join_room(task_id)
    emit('subscribed', {'task_id': task_id})

@socketio.on('unsubscribe_analysis')
def handle_analysis_unsubscription(data):
    """Unsubscribe from analysis updates"""
    task_id = data['task_id']
    leave_room(task_id)
    emit('unsubscribed', {'task_id': task_id})

def send_analysis_update(task_id, update_data):
    """Send real-time update to subscribers"""
    socketio.emit('analysis_update', update_data, room=task_id)

# Integration with analysis process
class RealtimeAnalyzer:
    def analyze_with_updates(self, domain, keyword, task_id):
        """Perform analysis with real-time updates"""
        
        # Send initial update
        send_analysis_update(task_id, {
            'status': 'started',
            'progress': 0,
            'message': 'Starting domain analysis'
        })
        
        # Domain analysis
        send_analysis_update(task_id, {
            'status': 'in_progress',
            'progress': 25,
            'message': 'Analyzing domain structure'
        })
        domain_result = self.analyze_domain_structure(domain, keyword)
        
        # Content analysis
        send_analysis_update(task_id, {
            'status': 'in_progress',
            'progress': 50,
            'message': 'Fetching and analyzing content'
        })
        content_result = self.analyze_content(domain)
        
        # Final scoring
        send_analysis_update(task_id, {
            'status': 'in_progress',
            'progress': 75,
            'message': 'Calculating risk score'
        })
        final_result = self.calculate_final_score(domain_result, content_result)
        
        # Complete
        send_analysis_update(task_id, {
            'status': 'completed',
            'progress': 100,
            'message': 'Analysis complete',
            'result': final_result
        })
        
        return final_result
```

## External Service Integration

### 1. Threat Intelligence APIs
```python
class ThreatIntelligenceIntegrator:
    def __init__(self):
        self.providers = {
            'virustotal': VirusTotalAPI(),
            'urlvoid': URLVoidAPI(),
            'phishtank': PhishTankAPI()
        }
    
    def check_domain_reputation(self, domain):
        """Check domain reputation across multiple providers"""
        reputation_data = {}
        
        for provider_name, provider in self.providers.items():
            try:
                result = provider.check_domain(domain)
                reputation_data[provider_name] = result
            except Exception as e:
                logger.warning(f"Failed to check {provider_name}: {e}")
                reputation_data[provider_name] = {'error': str(e)}
        
        return self.aggregate_reputation_data(reputation_data)
    
    def aggregate_reputation_data(self, reputation_data):
        """Aggregate reputation data from multiple sources"""
        total_score = 0
        valid_sources = 0
        
        for provider, data in reputation_data.items():
            if 'error' not in data and 'score' in data:
                total_score += data['score']
                valid_sources += 1
        
        if valid_sources == 0:
            return {'reputation_score': 0.5, 'confidence': 0}
        
        avg_score = total_score / valid_sources
        confidence = valid_sources / len(self.providers)
        
        return {
            'reputation_score': avg_score,
            'confidence': confidence,
            'sources': reputation_data
        }

class VirusTotalAPI:
    def __init__(self):
        self.api_key = os.getenv('VIRUSTOTAL_API_KEY')
        self.base_url = 'https://www.virustotal.com/vtapi/v2'
    
    def check_domain(self, domain):
        """Check domain with VirusTotal API"""
        params = {
            'apikey': self.api_key,
            'domain': domain
        }
        
        response = requests.get(f'{self.base_url}/domain/report', params=params)
        
        if response.status_code == 200:
            data = response.json()
            return self.parse_virustotal_response(data)
        else:
            raise APIError(f"VirusTotal API error: {response.status_code}")
    
    def parse_virustotal_response(self, data):
        """Parse VirusTotal API response"""
        if data.get('response_code') == 1:
            detected_urls = data.get('detected_urls', [])
            malicious_count = len(detected_urls)
            
            # Calculate risk score based on detections
            if malicious_count == 0:
                score = 0.1
            elif malicious_count < 5:
                score = 0.5
            else:
                score = 0.9
            
            return {
                'score': score,
                'detected_urls': malicious_count,
                'last_analysis': data.get('scan_date')
            }
        else:
            return {'score': 0.5, 'message': 'Domain not found in database'}
```

### 2. DNS and WHOIS Integration
```python
import dns.resolver
import whois
from datetime import datetime, timedelta

class DNSAnalyzer:
    def __init__(self):
        self.suspicious_nameservers = [
            'ns1.suspended-domain.com',
            'ns2.suspended-domain.com'
        ]
    
    def analyze_dns_records(self, domain):
        """Analyze DNS records for suspicious patterns"""
        dns_data = {}
        
        try:
            # A records
            a_records = dns.resolver.resolve(domain, 'A')
            dns_data['a_records'] = [str(record) for record in a_records]
            
            # MX records
            try:
                mx_records = dns.resolver.resolve(domain, 'MX')
                dns_data['mx_records'] = [str(record) for record in mx_records]
            except:
                dns_data['mx_records'] = []
            
            # NS records
            ns_records = dns.resolver.resolve(domain, 'NS')
            dns_data['ns_records'] = [str(record) for record in ns_records]
            
            # Analyze for suspicious patterns
            dns_data['suspicious_indicators'] = self.find_dns_indicators(dns_data)
            
        except Exception as e:
            dns_data['error'] = str(e)
        
        return dns_data
    
    def find_dns_indicators(self, dns_data):
        """Find suspicious DNS indicators"""
        indicators = []
        
        # Check for suspicious nameservers
        for ns in dns_data.get('ns_records', []):
            if any(suspicious in str(ns) for suspicious in self.suspicious_nameservers):
                indicators.append(f"Suspicious nameserver: {ns}")
        
        # Check for missing MX records (unusual for legitimate sites)
        if not dns_data.get('mx_records'):
            indicators.append("No MX records found")
        
        # Check for single A record (may indicate simple hosting)
        if len(dns_data.get('a_records', [])) == 1:
            indicators.append("Single A record")
        
        return indicators

class WHOISAnalyzer:
    def analyze_whois_data(self, domain):
        """Analyze WHOIS data for suspicious patterns"""
        try:
            w = whois.whois(domain)
            
            whois_data = {
                'creation_date': w.creation_date,
                'expiration_date': w.expiration_date,
                'registrar': w.registrar,
                'name_servers': w.name_servers,
                'status': w.status
            }
            
            # Analyze for suspicious patterns
            whois_data['suspicious_indicators'] = self.find_whois_indicators(whois_data)
            
            return whois_data
            
        except Exception as e:
            return {'error': str(e)}
    
    def find_whois_indicators(self, whois_data):
        """Find suspicious WHOIS indicators"""
        indicators = []
        
        # Check domain age
        creation_date = whois_data.get('creation_date')
        if creation_date:
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            
            age_days = (datetime.now() - creation_date).days
            if age_days < 30:
                indicators.append(f"Very new domain ({age_days} days old)")
            elif age_days < 90:
                indicators.append(f"Recently created domain ({age_days} days old)")
        
        # Check expiration date
        expiration_date = whois_data.get('expiration_date')
        if expiration_date:
            if isinstance(expiration_date, list):
                expiration_date = expiration_date[0]
            
            days_until_expiry = (expiration_date - datetime.now()).days
            if days_until_expiry < 30:
                indicators.append(f"Domain expires soon ({days_until_expiry} days)")
        
        # Check for privacy protection
        registrar = whois_data.get('registrar', '').lower()
        if 'privacy' in registrar or 'whoisguard' in registrar:
            indicators.append("Privacy protection enabled")
        
        return indicators
```

## API Documentation and Testing

### 1. OpenAPI Specification
```yaml
# api-spec.yaml
openapi: 3.0.0
info:
  title: Phishing Detection API
  version: 1.0.0
  description: API for analyzing domains for phishing indicators

servers:
  - url: https://api.phishing-detector.com/v1
    description: Production server

security:
  - ApiKeyAuth: []

paths:
  /analyze:
    post:
      summary: Analyze single domain
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/AnalysisRequest'
      responses:
        '200':
          description: Analysis completed successfully
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/AnalysisResult'
        '400':
          description: Invalid request
        '401':
          description: Unauthorized
        '429':
          description: Rate limit exceeded

components:
  securitySchemes:
    ApiKeyAuth:
      type: apiKey
      in: header
      name: X-API-Key
  
  schemas:
    AnalysisRequest:
      type: object
      required:
        - domain
        - keyword
      properties:
        domain:
          type: string
          example: "suspicious-site.com"
        keyword:
          type: string
          example: "sbi"
        options:
          type: object
          properties:
            include_screenshot:
              type: boolean
              default: false
            deep_analysis:
              type: boolean
              default: true
            timeout:
              type: integer
              default: 15
    
    AnalysisResult:
      type: object
      properties:
        domain:
          type: string
        keyword:
          type: string
        risk_score:
          type: number
          minimum: 0
          maximum: 1
        is_phishing:
          type: boolean
        confidence:
          type: number
          minimum: 0
          maximum: 1
        analysis_timestamp:
          type: string
          format: date-time
        indicators:
          type: array
          items:
            type: string
```

### 2. API Testing Framework
```python
import pytest
import requests
from unittest.mock import Mock, patch

class TestPhishingDetectionAPI:
    def setup_method(self):
        self.base_url = "http://localhost:5000/api/v1"
        self.api_key = "test_api_key_123"
        self.headers = {"X-API-Key": self.api_key}
    
    def test_analyze_domain_success(self):
        """Test successful domain analysis"""
        payload = {
            "domain": "test-phishing-site.com",
            "keyword": "sbi"
        }
        
        response = requests.post(
            f"{self.base_url}/analyze",
            json=payload,
            headers=self.headers
        )
        
        assert response.status_code == 200
        data = response.json()
        
        assert "risk_score" in data
        assert "is_phishing" in data
        assert 0 <= data["risk_score"] <= 1
        assert isinstance(data["is_phishing"], bool)
    
    def test_analyze_domain_invalid_input(self):
        """Test analysis with invalid input"""
        payload = {
            "domain": "",  # Invalid empty domain
            "keyword": "sbi"
        }
        
        response = requests.post(
            f"{self.base_url}/analyze",
            json=payload,
            headers=self.headers
        )
        
        assert response.status_code == 400
        assert "error" in response.json()
    
    def test_rate_limiting(self):
        """Test API rate limiting"""
        payload = {
            "domain": "test-site.com",
            "keyword": "sbi"
        }
        
        # Make multiple rapid requests
        responses = []
        for _ in range(15):  # Exceed rate limit
            response = requests.post(
                f"{self.base_url}/analyze",
                json=payload,
                headers=self.headers
            )
            responses.append(response.status_code)
        
        # Should get rate limited
        assert 429 in responses
    
    @patch('phishing_detector.analyze_domain')
    def test_analysis_timeout_handling(self, mock_analyze):
        """Test handling of analysis timeouts"""
        mock_analyze.side_effect = TimeoutError("Analysis timeout")
        
        payload = {
            "domain": "slow-site.com",
            "keyword": "sbi"
        }
        
        response = requests.post(
            f"{self.base_url}/analyze",
            json=payload,
            headers=self.headers
        )
        
        assert response.status_code == 500
        assert "timeout" in response.json()["error"].lower()

# Performance testing
class TestAPIPerformance:
    def test_analysis_performance(self):
        """Test analysis performance requirements"""
        import time
        
        payload = {
            "domain": "performance-test-site.com",
            "keyword": "sbi"
        }
        
        start_time = time.time()
        
        response = requests.post(
            f"{self.base_url}/analyze",
            json=payload,
            headers=self.headers
        )
        
        end_time = time.time()
        response_time = end_time - start_time
        
        # Should complete within 30 seconds
        assert response_time < 30
        assert response.status_code == 200
```