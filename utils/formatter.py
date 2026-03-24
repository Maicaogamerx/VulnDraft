#!/usr/bin/env python3
"""
Formatter Module - Text formatting and beautification
"""

import re
from typing import List, Dict, Any


class ReportFormatter:
    """
    Formats report content for consistent output
    """
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize formatter with configuration"""
        self.config = config
    
    def format_description(self, description: str) -> str:
        """
        Format vulnerability description
        
        Args:
            description: Raw description text
            
        Returns:
            Formatted description
        """
        if not description:
            return "No description provided."
        
        # Ensure proper line breaks
        description = description.strip()
        
        # Capitalize first letter
        if description and description[0].islower():
            description = description[0].upper() + description[1:]
        
        # Add period if missing
        if description and description[-1] not in '.!?':
            description += '.'
        
        return description
    
    def format_steps(self, steps: List[str]) -> List[str]:
        """
        Format steps to reproduce
        
        Args:
            steps: List of step strings
            
        Returns:
            Formatted steps list
        """
        formatted = []
        
        for i, step in enumerate(steps, 1):
            step = step.strip()
            if not step:
                continue
            
            # Capitalize first letter
            if step and step[0].islower():
                step = step[0].upper() + step[1:]
            
            # Add period if missing
            if step and step[-1] not in '.!?':
                step += '.'
            
            formatted.append(step)
        
        return formatted if formatted else ["No steps provided."]
    
    def format_cvss_vector(self, vector: str) -> str:
        """
        Format CVSS vector string for display
        
        Args:
            vector: Raw CVSS vector
            
        Returns:
            Formatted vector
        """
        if not vector:
            return ""
        
        # Add spaces between metrics for readability
        vector = vector.replace('/', ' / ')
        
        # Highlight the CVSS prefix
        vector = vector.replace('CVSS:3.1', '**CVSS:3.1**')
        
        return vector
    
    def generate_report_id(self) -> str:
        """
        Generate unique report ID
        
        Returns:
            Formatted report ID
        """
        from datetime import datetime
        return f"BRG-{datetime.now().strftime('%Y%m%d-%H%M%S')}"