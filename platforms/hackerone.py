#!/usr/bin/env python3
"""
HackerOne Platform Validator
Validates report fields according to HackerOne standards
"""

from typing import Dict, List, Optional, Tuple
import re


class HackerOneValidator:
    """
    Validator for HackerOne-specific report requirements
    
    HackerOne expects:
    - Clear vulnerability title
    - Detailed description with impact
    - Steps to reproduce with exact URLs
    - CVSS score (optional but recommended)
    - Proof of Concept (strongly recommended)
    """
    
    # HackerOne severity mapping
    SEVERITY_MAP = {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "info": "Informational"
    }
    
    # Required sections for HackerOne reports
    REQUIRED_SECTIONS = [
        "title",
        "description",
        "steps_to_reproduce",
        "impact"
    ]
    
    @classmethod
    def validate_report(cls, report_data: Dict) -> Tuple[bool, List[str]]:
        """
        Validate report data for HackerOne submission
        
        Args:
            report_data: Dictionary containing report data
            
        Returns:
            Tuple[bool, List[str]]: (is_valid, warnings)
        """
        warnings = []
        
        # Check required sections
        for section in cls.REQUIRED_SECTIONS:
            if section not in report_data or not report_data[section]:
                warnings.append(f"Missing required section: {section}")
        
        # Validate title (should be specific)
        title = report_data.get("title", "")
        if len(title) < 10:
            warnings.append("Title should be more descriptive (min 10 chars)")
        if any(x in title.lower() for x in ["bug", "issue", "problem"]):
            warnings.append("Avoid generic terms like 'bug' or 'issue' in title")
        
        # Validate description length
        description = report_data.get("description", "")
        if len(description) < 100:
            warnings.append("Description should be more detailed (min 100 chars)")
        
        # Validate steps to reproduce
        steps = report_data.get("steps_to_reproduce", [])
        if len(steps) < 2:
            warnings.append("Provide at least 2-3 detailed steps to reproduce")
        
        # Check for URLs in steps (good practice)
        steps_text = " ".join(steps)
        if not re.search(r'https?://', steps_text):
            warnings.append("Steps should include exact URLs where vulnerability occurs")
        
        # Validate impact section
        impact = report_data.get("impact", "")
        if len(impact) < 50:
            warnings.append("Impact section should describe business impact in detail")
        
        # Check for CVSS
        cvss_score = report_data.get("cvss_score")
        if cvss_score is None:
            warnings.append("CVSS score is recommended for HackerOne reports")
        
        return len([w for w in warnings if "Missing" in w]) == 0, warnings
    
    @classmethod
    def format_for_platform(cls, report_data: Dict) -> Dict:
        """
        Format report data specifically for HackerOne
        
        Args:
            report_data: Raw report data
            
        Returns:
            Formatted data for HackerOne
        """
        formatted = {
            "title": report_data.get("title", ""),
            "description": cls._format_description(report_data.get("description", "")),
            "steps_to_reproduce": cls._format_steps(report_data.get("steps_to_reproduce", [])),
            "impact": cls._format_impact(report_data.get("impact", "")),
        }
        
        # Add CVSS if present
        if report_data.get("cvss_score"):
            formatted["cvss_score"] = report_data["cvss_score"]
            formatted["cvss_vector"] = report_data.get("cvss_vector", "")
        
        # Add PoC if present
        if report_data.get("poc"):
            formatted["proof_of_concept"] = report_data["poc"]
        
        # Add affected components
        if report_data.get("affected_components"):
            formatted["affected_components"] = report_data["affected_components"]
        
        return formatted
    
    @classmethod
    def _format_description(cls, description: str) -> str:
        """Format description for HackerOne"""
        # HackerOne likes structured descriptions
        if "Vulnerability Type:" not in description:
            # Try to detect vulnerability type from content
            vuln_types = ["SQL Injection", "XSS", "CSRF", "IDOR", "RCE", "SSRF"]
            detected = None
            for vt in vuln_types:
                if vt.lower() in description.lower():
                    detected = vt
                    break
            
            if detected:
                description = f"**Vulnerability Type:** {detected}\n\n{description}"
        
        return description
    
    @classmethod
    def _format_steps(cls, steps: List[str]) -> List[str]:
        """Format steps for HackerOne"""
        # Ensure steps include URLs and specific actions
        formatted = []
        for i, step in enumerate(steps, 1):
            # Add URL placeholder if missing
            if not re.search(r'https?://', step) and "url" not in step.lower():
                step = f"{step} (use actual target URL: [TARGET_URL])"
            formatted.append(step)
        return formatted
    
    @classmethod
    def _format_impact(cls, impact: str) -> str:
        """Format impact for HackerOne"""
        if not impact:
            return "No impact description provided."
        
        # HackerOne expects business impact
        if "business" not in impact.lower() and "financial" not in impact.lower():
            impact = f"**Business Impact:**\n{impact}\n\n*Please describe any financial, reputational, or operational impact.*"
        
        return impact