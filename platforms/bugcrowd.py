#!/usr/bin/env python3
"""
Bugcrowd Platform Validator
Validates report fields according to Bugcrowd standards
"""

from typing import Dict, List, Tuple, Optional
import re


class BugcrowdValidator:
    """
    Validator for Bugcrowd-specific report requirements
    
    Bugcrowd expects:
    - Clear vulnerability title with type prefix
    - Detailed description
    - Steps to reproduce with exact details
    - Proof of Concept (required for high/critical)
    - CVSS score (required)
    """
    
    # Bugcrowd severity mapping
    SEVERITY_MAP = {
        "critical": "P1 - Critical",
        "high": "P2 - High",
        "medium": "P3 - Medium",
        "low": "P4 - Low",
        "info": "P5 - Informational"
    }
    
    # Vulnerability type prefixes (Bugcrowd style)
    VULN_PREFIXES = {
        "sql injection": "[SQLi]",
        "xss": "[XSS]",
        "csrf": "[CSRF]",
        "idor": "[IDOR]",
        "rce": "[RCE]",
        "ssrf": "[SSRF]",
        "xxe": "[XXE]",
        "open redirect": "[Open Redirect]",
        "information disclosure": "[Info Disclosure]"
    }
    
    @classmethod
    def validate_report(cls, report_data: Dict) -> Tuple[bool, List[str]]:
        """
        Validate report data for Bugcrowd submission
        
        Args:
            report_data: Dictionary containing report data
            
        Returns:
            Tuple[bool, List[str]]: (is_valid, warnings)
        """
        warnings = []
        
        # Validate title has prefix
        title = report_data.get("title", "")
        has_prefix = any(prefix in title for prefix in cls.VULN_PREFIXES.values())
        if not has_prefix:
            warnings.append("Title should include vulnerability type prefix (e.g., [SQLi])")
        
        # Validate description has affected component
        description = report_data.get("description", "")
        if "affected" not in description.lower() and "component" not in description.lower():
            warnings.append("Description should specify affected components/endpoints")
        
        # Validate steps are detailed
        steps = report_data.get("steps_to_reproduce", [])
        if len(steps) < 3:
            warnings.append("Provide at least 3 detailed steps to reproduce")
        
        # Check for specific technical details
        steps_text = " ".join(steps)
        if not any(x in steps_text.lower() for x in ["request", "response", "payload", "parameter"]):
            warnings.append("Steps should include technical details (request/response/payload)")
        
        # Validate PoC for high/critical
        severity = report_data.get("severity", "").lower()
        poc = report_data.get("poc", "")
        if severity in ["critical", "high"] and not poc:
            warnings.append("Proof of Concept is required for high/critical severity findings")
        
        # Validate CVSS
        cvss_score = report_data.get("cvss_score")
        if cvss_score is None:
            warnings.append("CVSS score is required for Bugcrowd reports")
        elif cvss_score >= 7.0 and not poc:
            warnings.append("High CVSS score requires proof of concept")
        
        return len([w for w in warnings if "required" in w.lower()]) == 0, warnings
    
    @classmethod
    def format_for_platform(cls, report_data: Dict) -> Dict:
        """
        Format report data specifically for Bugcrowd
        
        Args:
            report_data: Raw report data
            
        Returns:
            Formatted data for Bugcrowd
        """
        title = report_data.get("title", "")
        
        # Add prefix if missing
        title_lower = title.lower()
        has_prefix = False
        for vuln_type, prefix in cls.VULN_PREFIXES.items():
            if vuln_type in title_lower:
                if not title.startswith(prefix):
                    title = f"{prefix} {title}"
                has_prefix = True
                break
        
        formatted = {
            "title": title,
            "description": cls._format_description(report_data.get("description", "")),
            "steps_to_reproduce": cls._format_steps(report_data.get("steps_to_reproduce", [])),
            "impact": report_data.get("impact", ""),
            "proof_of_concept": cls._format_poc(report_data.get("poc", "")),
        }
        
        # Add CVSS
        if report_data.get("cvss_score"):
            formatted["cvss_score"] = report_data["cvss_score"]
            formatted["cvss_vector"] = report_data.get("cvss_vector", "")
            formatted["cvss_severity"] = cls.SEVERITY_MAP.get(
                report_data.get("severity", "").lower(), "P3 - Medium"
            )
        
        # Add affected components
        if report_data.get("affected_components"):
            formatted["affected_components"] = report_data["affected_components"]
        
        # Add remediation
        if report_data.get("remediation"):
            formatted["remediation"] = report_data["remediation"]
        
        return formatted
    
    @classmethod
    def _format_description(cls, description: str) -> str:
        """Format description for Bugcrowd"""
        # Bugcrowd likes technical details
        if "**Affected Component:**" not in description:
            description = f"**Affected Component:** \n\n{description}"
        return description
    
    @classmethod
    def _format_steps(cls, steps: List[str]) -> List[str]:
        """Format steps for Bugcrowd"""
        formatted = []
        for step in steps:
            # Ensure steps have technical detail
            if not any(x in step.lower() for x in ["http", "request", "response", "payload"]):
                step = f"{step}\n   → *Technical detail: Include exact request/response here*"
            formatted.append(step)
        return formatted
    
    @classmethod
    def _format_poc(cls, poc: str) -> str:
        """Format proof of concept for Bugcrowd"""
        if not poc:
            return ""
        
        # Ensure PoC is properly formatted
        if "```" not in poc:
            poc = f"```\n{poc}\n```"
        
        return poc