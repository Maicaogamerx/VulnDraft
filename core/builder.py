#!/usr/bin/env python3
"""
Report Builder Module
Assembles vulnerability data into final report structure
"""

import json
from typing import Dict, List, Any, Optional
from datetime import datetime
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from api.schemas import Report, Vulnerability
from utils.formatter import ReportFormatter


class ReportBuilder:
    """
    Builds final report structure from vulnerabilities
    Handles aggregation, validation, and formatting
    """
    
    def __init__(self, config: Dict):
        """
        Initialize builder with configuration
        
        Args:
            config: Configuration dictionary from config.json
        """
        self.config = config
        self.formatter = ReportFormatter(config)
    
    def build_report_dict(self, report: Report) -> Dict[str, Any]:
        """
        Convert Report object to dictionary with additional metadata
        
        Args:
            report: Report object
            
        Returns:
            Dict ready for template rendering
        """
        # Get summary
        summary = report.get_summary()
        
        # Build report data
        report_dict = {
            "report_id": report.report_id,
            "report_title": report.report_title,
            "author": report.author,
            "platform": report.platform,
            "target": report.target,
            "date": report.date.strftime("%Y-%m-%d %H:%M:%S"),
            "vulnerabilities": [],
            "summary": summary,
            "metadata": {
                "generator": self.config.get("app_name", "Bug Report Generator"),
                "version": self.config.get("version", "1.0.0"),
                "generated_at": datetime.now().isoformat()
            }
        }
        
        # Add each vulnerability with formatting
        for vuln in report.vulnerabilities:
            vuln_dict = {
                "id": len(report_dict["vulnerabilities"]) + 1,
                "title": vuln.title,
                "description": self.formatter.format_description(vuln.description),
                "steps_to_reproduce": self.formatter.format_steps(vuln.steps_to_reproduce),
                "impact": vuln.impact or "No impact description provided.",
                "poc": vuln.poc,
                "severity": vuln.severity or "info",
                "cvss_score": vuln.cvss_score,
                "cvss_vector": vuln.cvss_vector,
                "created_at": vuln.created_at.strftime("%Y-%m-%d %H:%M:%S")
            }
            report_dict["vulnerabilities"].append(vuln_dict)
        
        return report_dict
    
    def validate_report(self, report: Report) -> List[str]:
        """
        Validate report for completeness
        
        Args:
            report: Report object to validate
            
        Returns:
            List of validation warnings/errors
        """
        warnings = []
        
        # Check required fields
        if not report.report_title or len(report.report_title) < 5:
            warnings.append("Report title is too short or missing")
        
        if not report.vulnerabilities:
            warnings.append("No vulnerabilities added to report")
        
        # Check each vulnerability
        for i, vuln in enumerate(report.vulnerabilities, 1):
            if not vuln.title or len(vuln.title) < 5:
                warnings.append(f"Vulnerability {i}: Title is too short")
            
            if not vuln.description or len(vuln.description) < 20:
                warnings.append(f"Vulnerability {i}: Description is too short")
            
            if not vuln.steps_to_reproduce:
                warnings.append(f"Vulnerability {i}: No steps to reproduce")
        
        return warnings