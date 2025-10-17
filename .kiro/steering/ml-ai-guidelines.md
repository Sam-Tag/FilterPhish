---
inclusion: always
---

# Machine Learning and AI Guidelines for Phishing Detection

## Overview
This document provides specific guidelines for implementing machine learning and artificial intelligence components in the phishing detection system, ensuring robust, accurate, and maintainable AI-driven analysis.

## ML/AI Architecture Principles

### 1. Ensemble Approach
Combine multiple detection methods for improved accuracy:
- **Traditional ML**: TF-IDF vectorization, cosine similarity
- **Pattern Recognition**: Rule-based phishing indicators
- **Computer Vision**: Visual similarity analysis (when applicable)
- **NLP Techniques**: Content analysis and language pattern detection

### 2. Feature Engineering Standards

#### Domain Features
```python
domain_features = {
    'length': len(domain),
    'subdomain_count': len(domain.split('.')) - 2,
    'has_numbers': bool(re.search(r'\d', domain)),
    'suspicious_tld': domain.endswith(SUSPICIOUS_TLDS),
    'edit_distance': calculate_edit_distance(domain, canonical),
    'character_entropy': calculate_entropy(domain)
}
```

#### Content Features
```python
content_features = {
    'urgent_word_count': count_urgent_words(text),
    'financial_keyword_density': calculate_keyword_density(text),
    'form_count': len(extract_forms(html)),
    'external_link_ratio': calculate_external_ratio(links),
    'ssl_score': calculate_ssl_score(response),
    'text_length': len(clean_text)
}
```

### 3. Model Selection Guidelines

#### Text Similarity Models
- **TF-IDF + Cosine Similarity**: Primary method for content comparison
- **Sentence Transformers**: For semantic similarity (advanced)
- **Jaccard Similarity**: For keyword overlap analysis
- **Levenshtein Distance**: For domain name comparison

#### Classification Models (Future Enhancement)
- **Random Forest**: Interpretable ensemble method
- **Gradient Boosting**: High accuracy for structured features
- **Neural Networks**: For complex pattern recognition
- **SVM**: For high-dimensional feature spaces

## Implementation Standards

### 1. Scikit-learn Integration
```python
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split

class MLPhishingDetector:
    def __init__(self):
        self.vectorizer = TfidfVectorizer(
            max_features=1000,
            stop_words='english',
            ngram_range=(1, 2),
            min_df=2
        )
        self.classifier = None  # Initialize when training data available
    
    def extract_features(self, domain_info):
        """Extract standardized feature vector"""
        pass
    
    def calculate_similarity(self, text1, text2):
        """Calculate content similarity"""
        pass
```

### 2. Feature Preprocessing
```python
def preprocess_text(text):
    """Standardized text preprocessing"""
    # Remove HTML tags
    text = re.sub(r'<[^>]+>', ' ', text)
    # Convert to lowercase
    text = text.lower()
    # Remove special characters
    text = re.sub(r'[^\w\s]', ' ', text)
    # Normalize whitespace
    text = re.sub(r'\s+', ' ', text).strip()
    return text

def normalize_features(features):
    """Normalize feature values to 0-1 range"""
    from sklearn.preprocessing import MinMaxScaler
    scaler = MinMaxScaler()
    return scaler.fit_transform(features)
```

### 3. Risk Score Calculation
```python
def calculate_weighted_risk_score(domain_score, content_score, similarity_score):
    """
    Calculate final risk score using weighted combination
    
    Args:
        domain_score: Domain-based risk (0-1)
        content_score: Content-based risk (0-1)  
        similarity_score: Similarity with legitimate site (0-1)
    
    Returns:
        float: Final risk score (0-1)
    """
    weights = {
        'domain': 0.4,
        'content': 0.5,
        'similarity': 0.1
    }
    
    # Invert similarity score (high similarity = low risk)
    similarity_risk = 1 - similarity_score
    
    final_score = (
        domain_score * weights['domain'] +
        content_score * weights['content'] +
        similarity_risk * weights['similarity']
    )
    
    return min(max(final_score, 0.0), 1.0)  # Clamp to [0,1]
```

## Computer Vision Guidelines

### 1. Screenshot Analysis
```python
from PIL import Image
import numpy as np
from skimage.metrics import structural_similarity as ssim

def calculate_visual_similarity(img1_bytes, img2_bytes):
    """Calculate visual similarity between screenshots"""
    try:
        # Load and preprocess images
        img1 = Image.open(BytesIO(img1_bytes)).convert('RGB')
        img2 = Image.open(BytesIO(img2_bytes)).convert('RGB')
        
        # Resize to standard dimensions
        size = (800, 600)
        img1 = img1.resize(size)
        img2 = img2.resize(size)
        
        # Convert to numpy arrays
        arr1 = np.array(img1)
        arr2 = np.array(img2)
        
        # Calculate SSIM
        similarity = ssim(arr1, arr2, multichannel=True)
        
        return similarity
    except Exception as e:
        logger.error(f"Visual similarity calculation failed: {e}")
        return 0.0
```

### 2. Logo Detection (Advanced)
```python
def detect_logo_similarity(screenshot, reference_logos):
    """
    Detect and compare logos in screenshots
    Requires OpenCV and template matching
    """
    import cv2
    
    # Convert screenshot to OpenCV format
    img = cv2.cvtColor(np.array(screenshot), cv2.COLOR_RGB2BGR)
    
    similarities = []
    for logo_template in reference_logos:
        # Template matching
        result = cv2.matchTemplate(img, logo_template, cv2.TM_CCOEFF_NORMED)
        _, max_val, _, _ = cv2.minMaxLoc(result)
        similarities.append(max_val)
    
    return max(similarities) if similarities else 0.0
```

## Natural Language Processing

### 1. Phishing Language Detection
```python
PHISHING_PATTERNS = {
    'urgency': [
        r'\b(urgent|immediate|expire[sd]?|suspend|act now|verify now)\b',
        r'\b(limited time|expires? (today|soon)|deadline)\b'
    ],
    'threats': [
        r'\b(account (will be )?closed|suspended|blocked|terminated)\b',
        r'\b(lose access|permanent(ly)? disabled)\b'
    ],
    'action_required': [
        r'\b(click here|verify (your )?account|update (your )?information)\b',
        r'\b(confirm (your )?identity|validate (your )?account)\b'
    ]
}

def analyze_phishing_language(text):
    """Analyze text for phishing language patterns"""
    text_lower = text.lower()
    indicators = {}
    
    for category, patterns in PHISHING_PATTERNS.items():
        matches = []
        for pattern in patterns:
            matches.extend(re.findall(pattern, text_lower))
        indicators[category] = len(matches)
    
    return indicators
```

### 2. Content Similarity Analysis
```python
def calculate_semantic_similarity(text1, text2):
    """Calculate semantic similarity using sentence transformers"""
    try:
        from sentence_transformers import SentenceTransformer
        
        model = SentenceTransformer('all-MiniLM-L6-v2')
        
        # Generate embeddings
        embeddings1 = model.encode([text1])
        embeddings2 = model.encode([text2])
        
        # Calculate cosine similarity
        similarity = cosine_similarity(embeddings1, embeddings2)[0][0]
        
        return similarity
    except ImportError:
        # Fallback to TF-IDF if sentence-transformers not available
        return calculate_tfidf_similarity(text1, text2)
```

## Model Training Guidelines (Future Enhancement)

### 1. Training Data Requirements
```python
# Minimum dataset requirements
TRAINING_DATA_REQUIREMENTS = {
    'phishing_samples': 1000,      # Confirmed phishing sites
    'legitimate_samples': 2000,    # Confirmed legitimate sites
    'validation_split': 0.2,       # 20% for validation
    'test_split': 0.1,            # 10% for final testing
    'feature_coverage': 0.95       # 95% feature coverage required
}
```

### 2. Model Evaluation Metrics
```python
def evaluate_model_performance(y_true, y_pred, y_scores):
    """Comprehensive model evaluation"""
    from sklearn.metrics import (
        accuracy_score, precision_score, recall_score, f1_score,
        roc_auc_score, confusion_matrix, classification_report
    )
    
    metrics = {
        'accuracy': accuracy_score(y_true, y_pred),
        'precision': precision_score(y_true, y_pred),
        'recall': recall_score(y_true, y_pred),
        'f1_score': f1_score(y_true, y_pred),
        'auc_roc': roc_auc_score(y_true, y_scores),
        'confusion_matrix': confusion_matrix(y_true, y_pred).tolist()
    }
    
    return metrics
```

### 3. Model Validation
```python
def validate_model_robustness(model, test_data):
    """Test model against adversarial examples and edge cases"""
    
    # Test against known false positives
    false_positive_rate = calculate_false_positive_rate(model, legitimate_domains)
    
    # Test against typosquatting variations
    typosquatting_detection_rate = test_typosquatting_detection(model)
    
    # Test performance on different TLDs
    tld_performance = test_tld_performance(model, test_data)
    
    return {
        'false_positive_rate': false_positive_rate,
        'typosquatting_detection': typosquatting_detection_rate,
        'tld_performance': tld_performance
    }
```

## Performance Optimization

### 1. Caching Strategies
```python
from functools import lru_cache
import pickle

class CachedAnalyzer:
    def __init__(self):
        self.similarity_cache = {}
        self.feature_cache = {}
    
    @lru_cache(maxsize=1000)
    def get_domain_features(self, domain):
        """Cache domain feature extraction"""
        return self.extract_domain_features(domain)
    
    def cache_similarity_results(self, domain1, domain2, similarity):
        """Cache similarity calculations"""
        key = tuple(sorted([domain1, domain2]))
        self.similarity_cache[key] = similarity
```

### 2. Batch Processing
```python
def batch_analyze_domains(domains, batch_size=10):
    """Process domains in batches for efficiency"""
    results = []
    
    for i in range(0, len(domains), batch_size):
        batch = domains[i:i + batch_size]
        
        # Process batch
        batch_results = []
        for domain_info in batch:
            result = analyze_single_domain(domain_info)
            batch_results.append(result)
        
        results.extend(batch_results)
        
        # Rate limiting between batches
        time.sleep(1)
    
    return results
```

## Error Handling and Robustness

### 1. Graceful Degradation
```python
def robust_analysis(domain, keyword):
    """Perform analysis with graceful degradation"""
    results = {
        'domain': domain,
        'keyword': keyword,
        'components_analyzed': [],
        'components_failed': []
    }
    
    # Domain analysis (always possible)
    try:
        domain_score = analyze_domain_structure(domain, keyword)
        results['domain_score'] = domain_score
        results['components_analyzed'].append('domain')
    except Exception as e:
        results['components_failed'].append(f'domain: {e}')
    
    # Content analysis (may fail due to network)
    try:
        content_score = analyze_content(domain)
        results['content_score'] = content_score
        results['components_analyzed'].append('content')
    except Exception as e:
        results['components_failed'].append(f'content: {e}')
        results['content_score'] = 0.5  # Default uncertain score
    
    # Calculate final score with available components
    results['final_score'] = calculate_available_score(results)
    
    return results
```

### 2. Input Validation
```python
def validate_input_data(domain, keyword):
    """Validate input parameters"""
    errors = []
    
    # Domain validation
    if not domain or not isinstance(domain, str):
        errors.append("Domain must be a non-empty string")
    elif not re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', domain):
        errors.append("Invalid domain format")
    
    # Keyword validation
    if not keyword or not isinstance(keyword, str):
        errors.append("Keyword must be a non-empty string")
    
    if errors:
        raise ValueError(f"Input validation failed: {'; '.join(errors)}")
    
    return True
```

## Monitoring and Metrics

### 1. Model Performance Tracking
```python
def track_analysis_metrics(results):
    """Track key performance metrics"""
    metrics = {
        'total_analyzed': len(results),
        'success_rate': len([r for r in results if not r.get('error')]) / len(results),
        'avg_processing_time': calculate_avg_processing_time(results),
        'risk_score_distribution': calculate_score_distribution(results),
        'component_failure_rates': calculate_component_failures(results)
    }
    
    # Log metrics for monitoring
    logger.info(f"Analysis metrics: {json.dumps(metrics, indent=2)}")
    
    return metrics
```

### 2. Continuous Learning
```python
def update_model_with_feedback(feedback_data):
    """Update model based on user feedback"""
    # Collect feedback on false positives/negatives
    false_positives = [item for item in feedback_data if item['feedback'] == 'false_positive']
    false_negatives = [item for item in feedback_data if item['feedback'] == 'false_negative']
    
    # Adjust thresholds or retrain model
    if len(false_positives) > 10:
        adjust_risk_thresholds(false_positives)
    
    if len(false_negatives) > 5:
        update_detection_patterns(false_negatives)
```