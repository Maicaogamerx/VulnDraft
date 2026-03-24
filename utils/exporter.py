#!/usr/bin/env python3
"""
Export Module - Handles report export to multiple formats
Supports Markdown, HTML, and JSON
"""

import json
import markdown
from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime
from jinja2 import Environment, FileSystemLoader, Template
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))


class ReportExporter:
    """
    Handles exporting reports to various formats
    Supports: Markdown (.md), HTML (.html), JSON (.json)
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize exporter with configuration
        
        Args:
            config: Configuration dictionary
        """
        self.config = config
        self.output_dir = Path(config.get("output_dir", "./output"))
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Setup Jinja2 for templates
        template_dir = Path(config.get("templates_dir", "./templates"))
        self.jinja_env = Environment(
            loader=FileSystemLoader(str(template_dir)),
            autoescape=True,
            trim_blocks=True,
            lstrip_blocks=True
        )
        
        # Add custom filters
        self.jinja_env.filters['severity_color'] = self._severity_color_filter
    
    def _severity_color_filter(self, severity: str) -> str:
        """Jinja filter to get severity color"""
        colors = {
            "critical": "#d73a49",
            "high": "#e36209",
            "medium": "#f66a0a",
            "low": "#6f42c1",
            "info": "#6a737d"
        }
        return colors.get(severity.lower(), "#0366d6")
    
    def export_markdown(self, report_data: Dict[str, Any], platform: str = "hackerone") -> str:
        """
        Export report to Markdown format
        
        Args:
            report_data: Dictionary with report data
            platform: Target platform (hackerone, bugcrowd, intigriti, custom)
            
        Returns:
            Path to generated file
        """
        # Select template based on platform
        template_name = f"{platform}.md" if platform != "custom" else "default.md"
        
        try:
            template = self.jinja_env.get_template(template_name)
        except Exception:
            # Fallback to default template
            template = self.jinja_env.get_template("default.md")
        
        # Render markdown
        markdown_content = template.render(**report_data)
        
        # Save to file
        filename = f"{report_data['report_id']}.md"
        filepath = self.output_dir / filename
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(markdown_content)
        
        return str(filepath)
    
    def export_html(self, report_data: Dict[str, Any], platform: str = "hackerone") -> str:
        """
        Export report to HTML format with styling
        
        Args:
            report_data: Dictionary with report data
            platform: Target platform
            
        Returns:
            Path to generated file
        """
        # First generate markdown
        md_path = self.export_markdown(report_data, platform)
        
        # Read markdown content
        with open(md_path, 'r', encoding='utf-8') as f:
            md_content = f.read()
        
        # Convert markdown to HTML
        html_content = markdown.markdown(
            md_content,
            extensions=[
                'extra',
                'codehilite',
                'toc',
                'nl2br',
                'sane_lists'
            ]
        )
        
        # Apply custom HTML template
        html_template = """
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>{{ report_title }} - Security Report</title>
            <style>
                * {
                    margin: 0;
                    padding: 0;
                    box-sizing: border-box;
                }
                
                body {
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', sans-serif;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    padding: 40px 20px;
                    line-height: 1.6;
                }
                
                .container {
                    max-width: 1000px;
                    margin: 0 auto;
                    background: white;
                    border-radius: 12px;
                    box-shadow: 0 20px 60px rgba(0,0,0,0.3);
                    overflow: hidden;
                }
                
                .header {
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    padding: 40px;
                }
                
                .header h1 {
                    font-size: 2.5em;
                    margin-bottom: 10px;
                }
                
                .header .meta {
                    opacity: 0.9;
                    font-size: 0.9em;
                    margin-top: 20px;
                }
                
                .content {
                    padding: 40px;
                }
                
                .vulnerability {
                    background: #f8f9fa;
                    border-left: 4px solid #667eea;
                    padding: 20px;
                    margin: 20px 0;
                    border-radius: 8px;
                }
                
                .vulnerability h2 {
                    color: #333;
                    margin-bottom: 15px;
                }
                
                .severity-badge {
                    display: inline-block;
                    padding: 4px 12px;
                    border-radius: 20px;
                    font-size: 0.8em;
                    font-weight: bold;
                    margin-left: 10px;
                }
                
                .severity-critical { background: #d73a49; color: white; }
                .severity-high { background: #e36209; color: white; }
                .severity-medium { background: #f66a0a; color: white; }
                .severity-low { background: #6f42c1; color: white; }
                .severity-info { background: #6a737d; color: white; }
                
                pre {
                    background: #2d2d2d;
                    color: #f8f8f2;
                    padding: 15px;
                    border-radius: 6px;
                    overflow-x: auto;
                    margin: 15px 0;
                }
                
                code {
                    background: #f4f4f4;
                    padding: 2px 6px;
                    border-radius: 3px;
                    font-family: 'Courier New', monospace;
                    font-size: 0.9em;
                }
                
                pre code {
                    background: none;
                    padding: 0;
                }
                
                .summary {
                    background: #e3f2fd;
                    padding: 20px;
                    border-radius: 8px;
                    margin-bottom: 30px;
                }
                
                .summary-stats {
                    display: flex;
                    gap: 20px;
                    flex-wrap: wrap;
                    margin-top: 15px;
                }
                
                .stat {
                    flex: 1;
                    text-align: center;
                    padding: 15px;
                    background: white;
                    border-radius: 8px;
                }
                
                .stat-value {
                    font-size: 2em;
                    font-weight: bold;
                    color: #667eea;
                }
                
                .footer {
                    background: #f8f9fa;
                    padding: 20px 40px;
                    text-align: center;
                    font-size: 0.8em;
                    color: #6c757d;
                    border-top: 1px solid #dee2e6;
                }
                
                @media (max-width: 768px) {
                    .header { padding: 20px; }
                    .content { padding: 20px; }
                    .stat-value { font-size: 1.5em; }
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>{{ report_title }}</h1>
                    <div class="meta">
                        <strong>Report ID:</strong> {{ report_id }}<br>
                        <strong>Date:</strong> {{ date }}<br>
                        <strong>Author:</strong> {{ author }}
                    </div>
                </div>
                
                <div class="content">
                    {% if target %}
                    <div class="summary">
                        <strong>🎯 Target:</strong> {{ target }}
                    </div>
                    {% endif %}
                    
                    <div class="summary">
                        <h3>📊 Executive Summary</h3>
                        <div class="summary-stats">
                            <div class="stat">
                                <div class="stat-value">{{ summary.total_bugs }}</div>
                                <div>Total Vulnerabilities</div>
                            </div>
                            {% if summary.avg_cvss > 0 %}
                            <div class="stat">
                                <div class="stat-value">{{ summary.avg_cvss }}</div>
                                <div>Average CVSS Score</div>
                            </div>
                            {% endif %}
                        </div>
                    </div>
                    
                    {{ content | safe }}
                </div>
                
                <div class="footer">
                    Generated by {{ generator }} v{{ version }}<br>
                    {{ generated_at }}
                </div>
            </div>
        </body>
        </html>
        """
        
        # Render final HTML
        html_template_obj = Template(html_template)
        final_html = html_template_obj.render(
            report_title=report_data['report_title'],
            report_id=report_data['report_id'],
            date=report_data['date'],
            author=report_data['author'],
            target=report_data.get('target', ''),
            summary=report_data.get('summary', {}),
            content=html_content,
            generator=report_data.get('metadata', {}).get('generator', 'Bug Report Generator'),
            version=report_data.get('metadata', {}).get('version', '1.0.0'),
            generated_at=report_data.get('metadata', {}).get('generated_at', datetime.now().isoformat())
        )
        
        # Save HTML
        filename = f"{report_data['report_id']}.html"
        filepath = self.output_dir / filename
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(final_html)
        
        return str(filepath)
    
    def export_json(self, report_data: Dict[str, Any]) -> str:
        """
        Export report to JSON format
        
        Args:
            report_data: Dictionary with report data
            
        Returns:
            Path to generated file
        """
        filename = f"{report_data['report_id']}.json"
        filepath = self.output_dir / filename
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, default=str, ensure_ascii=False)
        
        return str(filepath)
    
    def export_all(self, report_data: Dict[str, Any], platform: str = "hackerone") -> Dict[str, str]:
        """
        Export report to all supported formats
        
        Args:
            report_data: Dictionary with report data
            platform: Target platform
            
        Returns:
            Dictionary with format to filepath mapping
        """
        return {
            "markdown": self.export_markdown(report_data, platform),
            "html": self.export_html(report_data, platform),
            "json": self.export_json(report_data)
        }