#!/usr/bin/env python3
"""
Validator Module - Input validation and sanitization
"""

import re
from typing import List, Optional, Tuple
from urllib.parse import urlparse


class InputValidator:
    """
    Validates user input for security and correctness
    """
    
    @staticmethod
    def validate_url(url: str) -> Tuple[bool, Optional[str]]:
        """
        Validate URL format
        
        Args:
            url: URL to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not url:
            return True, None
        
        try:
            parsed = urlparse(url)
            if not parsed.scheme or not parsed.netloc:
                return False, "Invalid URL format. Include http:// or https://"
            if parsed.scheme not in ['http', 'https']:
                return False, "Only HTTP and HTTPS URLs are supported"
            return True, None
        except Exception:
            return False, "Invalid URL format"
    
    @staticmethod
    def sanitize_text(text: str, max_length: int = 5000) -> str:
        """
        Sanitize text input
        
        Args:
            text: Input text
            max_length: Maximum allowed length
            
        Returns:
            Sanitized text
        """
        if not text:
            return ""
        
        # Remove excessive whitespace
        text = re.sub(r'\s+', ' ', text)
        
        # Trim to max length
        if len(text) > max_length:
            text = text[:max_length] + "..."
        
        return text.strip()
    
    @staticmethod
    def validate_steps(steps: List[str]) -> List[str]:
        """
        Validate and clean steps to reproduce
        
        Args:
            steps: List of step strings
            
        Returns:
            Cleaned steps list
        """
        cleaned = []
        for step in steps:
            step = step.strip()
            if step:
                cleaned.append(step)
        
        return cleaned if cleaned else ["No steps provided"]