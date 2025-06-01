import re
import logging
from typing import Dict, List, Tuple

logger = logging.getLogger(__name__)

class ScamDetector:
    """
    UPI transaction message scam detector using keyword and pattern matching
    """
    
    def __init__(self):
        """Initialize the scam detector with predefined patterns"""
        self.scam_patterns = self._load_scam_patterns()
        logger.info(f"Initialized ScamDetector with {len(self.scam_patterns)} patterns")
    
    def _load_scam_patterns(self) -> Dict[str, List[str]]:
        """
        Load predefined scam patterns categorized by type
        Returns a dictionary with pattern categories as keys and regex patterns as values
        """
        patterns = {
            # KYC and verification scams
            "kyc_scams": [
                r"\burgent\s+kyc\b",
                r"\bkyc\s+update\b",
                r"\bkyc\s+verification\b",
                r"\bverify\s+your\s+account\b",
                r"\baccount\s+will\s+be\s+blocked\b",
                r"\bupdate\s+your\s+kyc\b",
                r"\bkyc\s+pending\b",
                r"\bverification\s+required\b",
                r"\bcomplete\s+your\s+kyc\b"
            ],
            
            # Prize and lottery scams
            "prize_scams": [
                r"\bfree\s+prize\b",
                r"\bcongratulations.*won\b",
                r"\blottery\s+winner\b",
                r"\bwon\s+\d+\s*(?:lakh|crore|rupees)\b",
                r"\bclaim\s+your\s+prize\b",
                r"\blucky\s+winner\b",
                r"\bfree\s+gift\b",
                r"\bwon\s+.*\s+rupees\b",
                r"\bcash\s+prize\b",
                r"\binstant\s+win\b"
            ],
            
            # Job offer scams
            "job_scams": [
                r"\bjob\s+offer\b",
                r"\bwork\s+from\s+home\b",
                r"\bearn\s+\d+.*per\s+day\b",
                r"\bpart\s+time\s+job\b",
                r"\bonline\s+job\b",
                r"\beasy\s+money\b",
                r"\bdaily\s+income\b",
                r"\bno\s+investment\b",
                r"\bguaranteed\s+income\b",
                r"\bdata\s+entry\s+job\b"
            ],
            
            # Investment and trading scams
            "investment_scams": [
                r"\bquick\s+money\b",
                r"\bdouble\s+your\s+money\b",
                r"\btrading\s+tips\b",
                r"\bguaranteed\s+profit\b",
                r"\bstock\s+tips\b",
                r"\binvestment\s+opportunity\b",
                r"\bhigh\s+returns\b",
                r"\brisk\s+free\b",
                r"\bmultiply\s+your\s+money\b",
                r"\bcrypto\s+trading\b"
            ],
            
            # Phishing and fake links
            "phishing_scams": [
                r"\bclick\s+here\s+now\b",
                r"\bupdate\s+your\s+details\b",
                r"\bverify\s+now\b",
                r"\blink\s+expires\b",
                r"\bimmediate\s+action\b",
                r"\blogin\s+to\s+verify\b",
                r"\bsecure\s+your\s+account\b",
                r"\bconfirm\s+your\s+identity\b"
            ],
            
            # Urgency and pressure tactics
            "urgency_scams": [
                r"\bact\s+now\b",
                r"\blimited\s+time\b",
                r"\bexpires\s+today\b",
                r"\bonly\s+\d+\s+hours\s+left\b",
                r"\bimmediate\s+action\s+required\b",
                r"\bdon't\s+miss\b",
                r"\bhurry\s+up\b",
                r"\blast\s+chance\b",
                r"\bexpiring\s+soon\b"
            ],
            
            # Fake payment notifications
            "fake_payment_scams": [
                r"\bmoney\s+credited\b",
                r"\bamount\s+deposited\b",
                r"\brefund\s+processed\b",
                r"\bcashback\s+received\b",
                r"\btransaction\s+successful\b",
                r"\bpayment\s+received\b",
                r"\bamount\s+transferred\b"
            ],
            
            # Suspicious requests
            "suspicious_requests": [
                r"\bsend\s+money\b",
                r"\btransfer\s+amount\b",
                r"\bshare\s+otp\b",
                r"\bshare\s+pin\b",
                r"\bprovide\s+password\b",
                r"\bbank\s+details\b",
                r"\bcard\s+number\b",
                r"\bcvv\s+number\b"
            ]
        }
        
        return patterns
    
    def _compile_patterns(self) -> List[Tuple[str, re.Pattern, str]]:
        """
        Compile all patterns into regex objects for efficient matching
        Returns list of tuples: (pattern_string, compiled_regex, category)
        """
        compiled = []
        for category, pattern_list in self.scam_patterns.items():
            for pattern in pattern_list:
                try:
                    compiled_pattern = re.compile(pattern, re.IGNORECASE | re.UNICODE)
                    compiled.append((pattern, compiled_pattern, category))
                except re.error as e:
                    logger.error(f"Invalid regex pattern '{pattern}' in category '{category}': {e}")
        
        return compiled
    
    def check_text(self, text: str) -> Dict:
        """
        Check if the given text contains scam patterns
        
        Args:
            text (str): The UPI transaction message to check
            
        Returns:
            Dict: {
                "is_scam": bool,
                "matched_keywords": List[str],
                "matched_patterns": List[str],
                "confidence_score": float,
                "text": str,
                "categories": List[str]
            }
        """
        if not text or not isinstance(text, str):
            return {
                "is_scam": False,
                "matched_keywords": [],
                "matched_patterns": [],
                "confidence_score": 0.0,
                "text": text,
                "categories": []
            }
        
        # Clean and normalize text
        normalized_text = self._normalize_text(text)
        
        # Compile patterns if not already done
        compiled_patterns = self._compile_patterns()
        
        matched_keywords = []
        matched_patterns = []
        categories = set()
        
        # Check each pattern against the text
        for pattern_str, compiled_pattern, category in compiled_patterns:
            matches = compiled_pattern.findall(normalized_text)
            if matches:
                matched_keywords.extend(matches)
                matched_patterns.append(pattern_str)
                categories.add(category)
        
        # Remove duplicates while preserving order
        matched_keywords = list(dict.fromkeys(matched_keywords))
        matched_patterns = list(dict.fromkeys(matched_patterns))
        categories = list(categories)
        
        # Calculate confidence score
        confidence_score = self._calculate_confidence_score(
            len(matched_patterns), 
            len(categories),
            len(normalized_text)
        )
        
        is_scam = len(matched_patterns) > 0
        
        # Log detection results
        if is_scam:
            logger.info(f"Scam detected: {len(matched_patterns)} patterns matched, confidence: {confidence_score:.2f}")
        
        return {
            "is_scam": is_scam,
            "matched_keywords": matched_keywords,
            "matched_patterns": matched_patterns,
            "confidence_score": confidence_score,
            "text": text,
            "categories": categories
        }
    
    def _normalize_text(self, text: str) -> str:
        """
        Normalize text for better pattern matching
        """
        # Convert to lowercase and strip whitespace
        normalized = text.lower().strip()
        
        # Replace multiple spaces with single space
        normalized = re.sub(r'\s+', ' ', normalized)
        
        # Remove special characters that might interfere with matching
        # but keep basic punctuation
        normalized = re.sub(r'[^\w\s\-.,!?]', ' ', normalized)
        
        return normalized
    
    def _calculate_confidence_score(self, num_patterns: int, num_categories: int, text_length: int) -> float:
        """
        Calculate confidence score based on number of patterns matched,
        categories involved, and text length
        """
        if num_patterns == 0:
            return 0.0
        
        # Base score from number of patterns
        pattern_score = min(num_patterns * 0.3, 0.9)
        
        # Bonus for multiple categories
        category_bonus = min(num_categories * 0.1, 0.3)
        
        # Adjust for text length (shorter texts with matches are more suspicious)
        if text_length < 50:
            length_multiplier = 1.2
        elif text_length < 100:
            length_multiplier = 1.1
        else:
            length_multiplier = 1.0
        
        confidence = (pattern_score + category_bonus) * length_multiplier
        
        # Cap at 1.0
        return min(confidence, 1.0)
    
    def get_all_patterns(self) -> Dict[str, List[str]]:
        """
        Get all loaded scam patterns for debugging/monitoring
        """
        return self.scam_patterns.copy()
    
    def add_custom_pattern(self, category: str, pattern: str) -> bool:
        """
        Add a custom pattern to the detector
        
        Args:
            category (str): Pattern category
            pattern (str): Regex pattern string
            
        Returns:
            bool: True if pattern was added successfully
        """
        try:
            # Validate the regex pattern
            re.compile(pattern, re.IGNORECASE | re.UNICODE)
            
            if category not in self.scam_patterns:
                self.scam_patterns[category] = []
            
            if pattern not in self.scam_patterns[category]:
                self.scam_patterns[category].append(pattern)
                logger.info(f"Added custom pattern '{pattern}' to category '{category}'")
                return True
            else:
                logger.warning(f"Pattern '{pattern}' already exists in category '{category}'")
                return False
                
        except re.error as e:
            logger.error(f"Invalid regex pattern '{pattern}': {e}")
            return False
