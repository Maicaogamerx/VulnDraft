#!/usr/bin/env python3
"""
FastAPI Routes for REST API
Provides programmatic access to report generation
"""

from fastapi import APIRouter, HTTPException, status
from typing import List, Optional
from datetime import datetime
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from api.schemas import Report, Vulnerability
from core.builder import ReportBuilder
from utils.exporter import ReportExporter
import json

# Load config
with open("config.json", "r") as f:
    config = json.load(f)

router = APIRouter(prefix="/api/v1", tags=["Report Generation"])
exporter = ReportExporter(config)
builder = ReportBuilder(config)


@router.post(
    "/reports",
    response_model=dict,
    status_code=status.HTTP_201_CREATED,
    summary="Generate a new report",
    description="Creates a new security report from vulnerability data"
)
async def create_report(report: Report):
    """
    Generate a complete security report
    
    - **report_title**: Title of the report
    - **author**: Author name
    - **platform**: Target platform (hackerone, bugcrowd, intigriti, custom)
    - **vulnerabilities**: List of vulnerabilities to include
    - **target**: Optional target URL or application
    """
    try:
        # Validate report
        warnings = builder.validate_report(report)
        
        # Build report dictionary
        report_dict = builder.build_report_dict(report)
        
        # Generate exports
        exports = {}
        
        # Export Markdown
        md_path = exporter.export_markdown(report_dict, report.platform)
        exports["markdown"] = md_path
        
        # Export HTML
        html_path = exporter.export_html(report_dict, report.platform)
        exports["html"] = html_path
        
        # Export JSON
        json_path = exporter.export_json(report_dict)
        exports["json"] = json_path
        
        return {
            "status": "success",
            "report_id": report.report_id,
            "exports": exports,
            "warnings": warnings,
            "summary": report.get_summary()
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate report: {str(e)}"
        )


@router.post(
    "/validate",
    response_model=dict,
    summary="Validate vulnerability data",
    description="Validates vulnerability data without generating report"
)
async def validate_vulnerabilities(vulnerabilities: List[Vulnerability]):
    """
    Validate vulnerability data structure
    
    Returns validation results without generating files
    """
    errors = []
    warnings = []
    
    for i, vuln in enumerate(vulnerabilities):
        try:
            # Validate title
            if len(vuln.title) < 5:
                errors.append(f"Vulnerability {i+1}: Title too short")
            
            # Validate description
            if len(vuln.description) < 20:
                errors.append(f"Vulnerability {i+1}: Description too short")
            
            # Validate steps
            if not vuln.steps_to_reproduce:
                errors.append(f"Vulnerability {i+1}: No steps to reproduce")
            
        except Exception as e:
            errors.append(f"Vulnerability {i+1}: {str(e)}")
    
    return {
        "valid": len(errors) == 0,
        "errors": errors,
        "warnings": warnings,
        "total_validated": len(vulnerabilities)
    }


@router.get(
    "/templates",
    response_model=dict,
    summary="List available templates",
    description="Returns list of available report templates"
)
async def list_templates():
    """Get list of available report templates"""
    templates = {
        "hackerone": {
            "name": "HackerOne Style",
            "description": "Template matching HackerOne report format",
            "fields": ["title", "description", "steps", "impact", "cvss"]
        },
        "bugcrowd": {
            "name": "Bugcrowd Style",
            "description": "Template matching Bugcrowd report format",
            "fields": ["title", "description", "steps", "impact", "cvss"]
        },
        "intigriti": {
            "name": "Intigriti Style",
            "description": "Template matching Intigriti report format",
            "fields": ["title", "description", "steps", "impact", "cvss"]
        },
        "custom": {
            "name": "Custom Template",
            "description": "Generic template for any platform",
            "fields": ["title", "description", "steps", "impact"]
        }
    }
    
    return {
        "templates": templates,
        "default": config.get("default_platform", "hackerone")
    }


@router.get(
    "/health",
    response_model=dict,
    summary="Health check",
    description="Check if the API is running"
)
async def health_check():
    """API health check endpoint"""
    return {
        "status": "healthy",
        "version": config.get("version", "1.0.0"),
        "timestamp": datetime.now().isoformat()
    }