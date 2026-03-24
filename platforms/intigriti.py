#!/usr/bin/env python3
"""
Intigriti Platform Validator
Validates report fields according to Intigriti standards
"""

from typing import Dict, List, Tuple, Optional
import re


class IntigritiValidator:
    """
    Validator for Intigriti-specific report requirements
    
    Intigriti expects:
    - Clear, concise title
    - Executive summary
    - Technical details section
    - Steps to reproduce
    - Impact assessment
    - Remediation advice
    """
    
    # Intigriti severity mapping
    SEVERITY_MAP = {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "info": "Informational"
    }
    
    @classmethod
    def validate_report(cls, report_data: Dict) -> Tuple[bool, List[str]]:
        """
        Validate report data for Intigriti submission
        
        Args:
            report_data: Dictionary containing report data
            
        Returns:
            Tuple[bool, List[str]]: (is_valid, warnings)
        """
        warnings = []
        
        # Validate title length
        title = report_data.get("title", "")
        if len(title) < 10 or len(title) > 100:
            warnings.append("Title should be between 10-100 characters")
        
        # Validate executive summary (description should have summary)
        description = report_data.get("description", "")
        if len(description) < 50:
            warnings.append("Description should be at least 50 characters")
        
        # Validate technical details section
        if "technical" not in description.lower() and "details" not in description.lower():
            warnings.append("Consider adding a 'Technical Details' section to description")
        
        # Validate steps
        steps = report_data.get("steps_to_reproduce", [])
        if len(steps) < 2:
            warnings.append("Provide at least 2 detailed steps to reproduce")
        
        # Check for remediation suggestion
        impact = report_data.get("impact", "")
        if "remediation" not in impact.lower() and "fix" not in impact.lower():
            warnings.append("Impact section should include remediation suggestions")
        
        # Validate CVSS (recommended)
        cvss_score = report_data.get("cvss_score")
        if cvss_score is None:
            warnings.append("CVSS score is recommended for Intigriti reports")
        
        # Check for environmental details
        env = report_data.get("environment", "")
        if not env:
            warnings.append("Specify test environment (version, configuration, etc.)")
        
        return len([w for w in warnings if "should" in w.lower()]) == 0, warnings
    
    @classmethod
    def format_for_platform(cls, report_data: Dict) -> Dict:
        """
        Format report data specifically for Intigriti
        
        Args:
            report_data: Raw report data
            
        Returns:
            Formatted data for Intigriti
        """
        formatted = {
            "title": cls._format_title(report_data.get("title", "")),
            "executive_summary": cls._format_summary(report_data.get("description", "")),
            "technical_details": cls._format_technical(report_data.get("description", "")),
            "steps_to_reproduce": cls._format_steps(report_data.get("steps_to_reproduce", [])),
            "impact_assessment": cls._format_impact(report_data.get("impact", "")),
        }
        
        # Add PoC
        if report_data.get("poc"):
            formatted["proof_of_concept"] = report_data["poc"]
        
        # Add CVSS
        if report_data.get("cvss_score"):
            formatted["cvss_score"] = report_data["cvss_score"]
            formatted["cvss_vector"] = report_data.get("cvss_vector", "")
            formatted["severity"] = cls.SEVERITY_MAP.get(
                report_data.get("severity", "").lower(), "Medium"
            )
        
        # Add environment
        if report_data.get("environment"):
            formatted["environment"] = report_data["environment"]
        
        # Add affected assets
        if report_data.get("target"):
            formatted["affected_assets"] = [report_data["target"]]
        
        return formatted
    
    @classmethod
    def _format_title(cls, title: str) -> str:
        """Format title for Intigriti"""
        # Intigriti likes concise titles
        if len(title) > 80:
            title = title[:77] + "..."
        return title
    
    @classmethod
    def _format_summary(cls, description: str) -> str:
        """Format executive summary"""
        # Extract first 3 sentences as summary
        sentences = re.split(r'[.!?]+', description)
        summary = ". ".join(sentences[:2]) + "."
        if len(summary) > 200:
            summary = summary[:197] + "..."
        return summary
    
    @classmethod
    def _format_technical(cls, description: str) -> str:
        """Format technical details section"""
        # Ensure technical details are structured
        if "**Technical Details:**" not in description:
            description = f"**Technical Details:**\n{description}"
        return description
    
    @classmethod
    def _format_steps(cls, steps: List[str]) -> List[str]:
        """Format steps for Intigriti"""
        formatted = []
        for i, step in enumerate(steps, 1):
            # Add step numbers clearly
            formatted.append(f"**Step {i}:** {step}")
        return formatted
    
    @classmethod
    def _format_impact(cls, impact: str) -> str:
        """Format impact assessment"""
        if not impact:
            return "No impact assessment provided."
        
        # Structure impact with business and technical impact
        if "**Business Impact:**" not in impact:
            impact = f"**Business Impact:**\n{impact}\n\n**Technical Impact:**\nSee technical details above."
        
        return impact