#!/usr/bin/env python3

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from advanced_phishing_detector import PhishingDetector
import json

def test_airtel_domain():
    """Test the airtelharyana.com domain specifically"""
    
    detector = PhishingDetector()
    
    # Test domain
    domain = "airtelharyana.com"
    keyword = "airtel"
    
    print(f"Analyzing {domain} for keyword '{keyword}'...")
    print("=" * 60)
    
    try:
        result = detector.analyze_domain(domain, keyword)
        
        print("RESULT KEYS:", list(result.keys()))
        print()
        print(json.dumps(result, indent=2, default=str))
        print()
        
        # Show detailed scoring breakdown
        if 'detailed_scores' in result:
            scores = result['detailed_scores']
            print("DETAILED SCORING:")
            print(f"Domain Score: {scores.get('domain_score', 'N/A'):.3f}")
            print(f"Content Score: {scores.get('content_score', 'N/A'):.3f}")
            print(f"Similarity Score: {scores.get('similarity_score', 'N/A'):.3f}")
            print()
        
        # Show content analysis if available
        if 'content_analysis' in result:
            content = result['content_analysis']
            print("CONTENT DETAILS:")
            if 'text_content' in content:
                text_preview = content['text_content'][:500] + "..." if len(content['text_content']) > 500 else content['text_content']
                print(f"Text Content Preview: {text_preview}")
            print()
        
        return result
        
    except Exception as e:
        print(f"Error analyzing domain: {e}")
        import traceback
        traceback.print_exc()
        return None

if __name__ == "__main__":
    test_airtel_domain()