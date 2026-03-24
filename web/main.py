#!/usr/bin/env python3
"""
Web Interface - FastAPI Application
Provides browser-based interface for report generation
"""

from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, HTMLResponse
from pathlib import Path
import json
import sys
import os

sys.path.insert(0, str(Path(__file__).parent.parent))

from api.schemas import Report, Vulnerability
from core.builder import ReportBuilder
from utils.exporter import ReportExporter

# Load config
with open("config.json", "r") as f:
    config = json.load(f)

# Create FastAPI app
app = FastAPI(
    title=config.get("app_name", "Bug Report Generator"),
    version=config.get("version", "1.0.0"),
    description="Generate professional security reports with ease"
)

# Setup templates and static files
templates_dir = Path(__file__).parent / "templates"
static_dir = Path(__file__).parent / "static"

templates = Jinja2Templates(directory=str(templates_dir))
app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

# Initialize components
exporter = ReportExporter(config)
builder = ReportBuilder(config)


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    """Home page - report input form"""
    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "title": config.get("app_name", "Bug Report Generator"),
            "version": config.get("version", "1.0.0")
        }
    )


@app.post("/generate")
async def generate_report(
    request: Request,
    report_title: str = Form(...),
    author: str = Form(...),
    target: str = Form(default=""),
    platform: str = Form(default="hackerone"),
    vulnerability_title: str = Form(...),
    vulnerability_description: str = Form(...),
    steps: str = Form(...),
    impact: str = Form(default=""),
    poc: str = Form(default="")
):
    """
    Generate report from form input
    """
    try:
        # Parse steps (one per line)
        steps_list = [step.strip() for step in steps.split('\n') if step.strip()]
        
        if not steps_list:
            steps_list = ["No steps provided"]
        
        # Create vulnerability
        vulnerability = Vulnerability(
            title=vulnerability_title,
            description=vulnerability_description,
            steps_to_reproduce=steps_list,
            impact=impact if impact else None,
            poc=poc if poc else None
        )
        
        # Create report
        report = Report(
            report_title=report_title,
            author=author,
            platform=platform,
            vulnerabilities=[vulnerability],
            target=target if target else None
        )
        
        # Build report dict
        report_dict = builder.build_report_dict(report)
        
        # Generate exports
        exports = exporter.export_all(report_dict, platform)
        
        return templates.TemplateResponse(
            "report.html",
            {
                "request": request,
                "report": report_dict,
                "exports": exports,
                "summary": report.get_summary()
            }
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error generating report: {str(e)}")


@app.get("/preview/{report_id}")
async def preview_report(request: Request, report_id: str):
    """Preview generated report"""
    # Find report file
    output_dir = Path(config.get("output_dir", "./output"))
    html_file = output_dir / f"{report_id}.html"
    
    if not html_file.exists():
        raise HTTPException(status_code=404, detail="Report not found")
    
    return FileResponse(str(html_file), media_type="text/html")


@app.get("/download/{report_id}/{format}")
async def download_report(request: Request, report_id: str, format: str):
    """Download report in specified format"""
    output_dir = Path(config.get("output_dir", "./output"))
    
    format_map = {
        "md": "markdown",
        "html": "html",
        "json": "json"
    }
    
    file_format = format_map.get(format, format)
    file_path = output_dir / f"{report_id}.{file_format}"
    
    if not file_path.exists():
        raise HTTPException(status_code=404, detail=f"Report not found in {file_format} format")
    
    # Determine MIME type
    mime_types = {
        "md": "text/markdown",
        "html": "text/html",
        "json": "application/json"
    }
    
    return FileResponse(
        str(file_path),
        media_type=mime_types.get(format, "application/octet-stream"),
        filename=f"{report_id}.{file_format}"
    )