import os
import json
import csv
import argparse
import base64
import io
import requests
from datetime import datetime
from jinja2 import Environment, FileSystemLoader
import pandas as pd
import markdown
import pdfkit
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from PIL import Image, ImageDraw, ImageFont
import matplotlib.pyplot as plt
import numpy as np
import tempfile
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image as RLImage, PageBreak
from reportlab.platypus.flowables import Flowable
from reportlab.pdfgen import canvas
from reportlab.lib.units import inch
import openai  # For AI integration


@dataclass
class Vulnerability:
    title: str
    severity: str
    description: str
    impact: str
    remediation: str
    cvss_score: float = 0.0
    cve_id: str = ""
    affected_components: List[str] = field(default_factory=list)
    proof_of_concept: str = ""
    references: List[str] = field(default_factory=list)
    status: str = "Open"


@dataclass
class VAPTReport:
    project_name: str
    client_name: str
    assessment_date: str
    scope: List[str]
    methodology: List[str]
    executive_summary: str
    vulnerabilities: List[Vulnerability]
    report_date: str = field(default_factory=lambda: datetime.now().strftime("%Y-%m-%d"))
    assessor_name: str = ""
    report_id: str = ""
    confidentiality_statement: str = "This report contains confidential information about the security posture of the client's systems."
    custom_fields: Dict[str, Any] = field(default_factory=dict)


class DataParser:
    """Base class for parsing different data formats"""
    def parse(self, file_path) -> List[Vulnerability]:
        raise NotImplementedError("Subclasses must implement this method")


class JSONParser(DataParser):
    """Parser for JSON vulnerability data"""
    def parse(self, file_path) -> List[Vulnerability]:
        with open(file_path, 'r') as f:
            data = json.load(f)
        
        vulnerabilities = []
        for item in data:
            vuln = Vulnerability(
                title=item.get('title', 'Untitled'),
                severity=item.get('severity', 'Unknown'),
                description=item.get('description', ''),
                impact=item.get('impact', ''),
                remediation=item.get('remediation', ''),
                cvss_score=float(item.get('cvss_score', 0.0)),
                cve_id=item.get('cve_id', ''),
                affected_components=item.get('affected_components', []),
                proof_of_concept=item.get('proof_of_concept', ''),
                references=item.get('references', []),
                status=item.get('status', 'Open')
            )
            vulnerabilities.append(vuln)
        
        return vulnerabilities


class CSVParser(DataParser):
    """Parser for CSV vulnerability data"""
    def parse(self, file_path) -> List[Vulnerability]:
        df = pd.read_csv(file_path)
        vulnerabilities = []
        
        for _, row in df.iterrows():
            vuln = Vulnerability(
                title=row.get('title', 'Untitled'),
                severity=row.get('severity', 'Unknown'),
                description=row.get('description', ''),
                impact=row.get('impact', ''),
                remediation=row.get('remediation', ''),
                cvss_score=float(row.get('cvss_score', 0.0)) if pd.notna(row.get('cvss_score', 0.0)) else 0.0,
                cve_id=row.get('cve_id', ''),
                affected_components=row.get('affected_components', '').split(',') if pd.notna(row.get('affected_components', '')) else [],
                proof_of_concept=row.get('proof_of_concept', ''),
                references=row.get('references', '').split(',') if pd.notna(row.get('references', '')) else [],
                status=row.get('status', 'Open')
            )
            vulnerabilities.append(vuln)
        
        return vulnerabilities


class NessusParser(DataParser):
    """Parser for Nessus XML output"""
    def parse(self, file_path) -> List[Vulnerability]:
        # Import here to avoid dependency if not used
        import xml.etree.ElementTree as ET
        
        tree = ET.parse(file_path)
        root = tree.getroot()
        vulnerabilities = []
        
        for report_host in root.findall(".//ReportHost"):
            hostname = report_host.get('name')
            
            for report_item in report_host.findall(".//ReportItem"):
                severity_map = {
                    '0': 'Info',
                    '1': 'Low',
                    '2': 'Medium', 
                    '3': 'High',
                    '4': 'Critical'
                }
                
                severity = severity_map.get(report_item.get('severity', '0'), 'Unknown')
                plugin_name = report_item.find('plugin_name')
                description = report_item.find('description')
                solution = report_item.find('solution')
                plugin_output = report_item.find('plugin_output')
                cvss_base_score = report_item.find('cvss_base_score')
                cve = report_item.find('cve')
                
                vuln = Vulnerability(
                    title=plugin_name.text if plugin_name is not None else 'Unknown',
                    severity=severity,
                    description=description.text if description is not None else '',
                    impact=f"Affects: {hostname}",
                    remediation=solution.text if solution is not None else '',
                    cvss_score=float(cvss_base_score.text) if cvss_base_score is not None else 0.0,
                    cve_id=cve.text if cve is not None else '',
                    affected_components=[hostname],
                    proof_of_concept=plugin_output.text if plugin_output is not None else '',
                    references=[]
                )
                vulnerabilities.append(vuln)
        
        return vulnerabilities


class AIEnhancer:
    """Class to enhance report content using AI"""
    def __init__(self, api_key=None):
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY")
        if self.api_key:
            openai.api_key = self.api_key
    
    def is_available(self):
        """Check if AI enhancement is available"""
        return bool(self.api_key)
    
    def enhance_executive_summary(self, report: VAPTReport) -> str:
        """Enhance executive summary with AI"""
        if not self.is_available():
            return report.executive_summary
            
        try:
            # Create a prompt for the AI to enhance the executive summary
            stats = report.custom_fields.get('statistics', {})
            stats_str = ", ".join([f"{k}: {v}" for k, v in stats.items() if v > 0])
            
            prompt = f"""
            Enhance the following executive summary for a vulnerability assessment and penetration testing report.
            Make it more professional and comprehensive, but maintain all the key information.
            
            Original summary: {report.executive_summary}
            
            Project: {report.project_name}
            Client: {report.client_name}
            Assessment date: {report.assessment_date}
            
            Findings summary: {stats_str}
            Overall risk score: {report.custom_fields.get('risk_score', 'N/A')}%
            
            The enhanced summary should be professional, clear, and concise. 
            It should summarize the assessment's purpose, methodology, key findings, and recommendations.
            """
            
            response = openai.Completion.create(
                engine="text-davinci-003",
                prompt=prompt,
                max_tokens=500,
                temperature=0.7
            )
            
            enhanced_summary = response.choices[0].text.strip()
            if enhanced_summary:
                return enhanced_summary
            return report.executive_summary
        except Exception as e:
            print(f"AI enhancement failed: {e}")
            return report.executive_summary
    
    def generate_remediation_checklist(self, vulnerabilities: List[Vulnerability]) -> Dict[str, List[str]]:
        """Generate a remediation checklist using AI"""
        if not self.is_available() or not vulnerabilities:
            return {}
            
        try:
            # Create a combined prompt from all remediation advice
            all_remediations = "\n".join([
                f"- {vuln.title} ({vuln.severity}): {vuln.remediation}" 
                for vuln in vulnerabilities if vuln.remediation
            ])
            
            prompt = f"""
            Based on the following vulnerability remediation recommendations, 
            create a practical checklist of actionable steps organized by system component or technology.
            
            Remediation recommendations:
            {all_remediations}
            
            Format the response as JSON with keys for different system components and values as arrays of checklist items.
            Example:
            {{
                "Web Application": ["Enable parameterized queries for all database operations", "Implement proper input validation"],
                "Network": ["Update firewall rules", "Implement network segmentation"]
            }}
            """
            
            response = openai.Completion.create(
                engine="text-davinci-003",
                prompt=prompt,
                max_tokens=1000,
                temperature=0.5
            )
            
            try:
                checklist = json.loads(response.choices[0].text.strip())
                return checklist
            except json.JSONDecodeError:
                print("AI response could not be parsed as JSON")
                return {}
                
        except Exception as e:
            print(f"AI checklist generation failed: {e}")
            return {}
    
    def prioritize_recommendations(self, vulnerabilities: List[Vulnerability]) -> Dict[str, List[str]]:
        """Create prioritized remediation roadmap"""
        if not self.is_available() or not vulnerabilities:
            return {}
            
        try:
            vuln_details = "\n".join([
                f"- {vuln.title} (Severity: {vuln.severity}, CVSS: {vuln.cvss_score})" 
                for vuln in vulnerabilities
            ])
            
            prompt = f"""
            Based on the following vulnerabilities, create a prioritized remediation roadmap 
            with immediate (1-2 weeks), short-term (1-3 months), and long-term (3-6 months) actions.
            Consider both severity and implementation complexity.
            
            Vulnerabilities:
            {vuln_details}
            
            Format the response as JSON with timeframe keys and arrays of recommendations.
            Example:
            {{
                "Immediate": ["Fix SQL injection in login form", "Update server software"],
                "Short-term": ["Implement WAF", "Security training for developers"],
                "Long-term": ["Architecture review", "Implement SAST/DAST in CI/CD pipeline"]
            }}
            """
            
            response = openai.Completion.create(
                engine="text-davinci-003",
                prompt=prompt,
                max_tokens=1000,
                temperature=0.5
            )
            
            try:
                roadmap = json.loads(response.choices[0].text.strip())
                return roadmap
            except json.JSONDecodeError:
                print("AI response could not be parsed as JSON")
                return {}
                
        except Exception as e:
            print(f"AI roadmap generation failed: {e}")
            return {}


class ChartGenerator:
    """Generate charts and graphs for the report"""
    @staticmethod
    def create_severity_pie_chart(stats, output_path=None):
        """Create a pie chart showing vulnerability severity distribution"""
        # Filter out zeros
        filtered_stats = {k: v for k, v in stats.items() if v > 0}
        
        # Set colors for different severity levels
        colors = {
            'Critical': '#dc3545',  # Red
            'High': '#fd7e14',      # Orange
            'Medium': '#ffc107',    # Yellow
            'Low': '#28a745',       # Green
            'Info': '#17a2b8',      # Blue
            'Unknown': '#6c757d'    # Gray
        }
        
        # Create figure
        plt.figure(figsize=(8, 6))
        
        # Get labels and values
        labels = filtered_stats.keys()
        values = filtered_stats.values()
        chart_colors = [colors.get(label, '#6c757d') for label in labels]
        
        # Create pie chart
        plt.pie(
            values, 
            labels=labels,
            colors=chart_colors,
            autopct='%1.1f%%',
            startangle=90,
            shadow=True,
            explode=[0.05] * len(filtered_stats)
        )
        plt.axis('equal')
        plt.title('Vulnerability Severity Distribution', fontsize=14)
        
        if output_path:
            plt.savefig(output_path, format='png', dpi=300, bbox_inches='tight')
            plt.close()
            return output_path
        else:
            # Return the figure as bytes
            buf = io.BytesIO()
            plt.savefig(buf, format='png', dpi=300, bbox_inches='tight')
            plt.close()
            buf.seek(0)
            return buf

    @staticmethod
    def create_risk_score_gauge(score, output_path=None):
        """Create a gauge chart showing the overall risk score"""
        fig, ax = plt.subplots(figsize=(8, 4))
        
        # Define the gauge
        gauge_min = 0
        gauge_max = 100
        
        # Create the gauge background
        theta = np.linspace(np.pi, 0, 100)
        r = 0.8
        x = r * np.cos(theta)
        y = r * np.sin(theta)
        
        # Define colors for different risk levels
        cmap = plt.cm.RdYlGn_r
        norm = plt.Normalize(gauge_min, gauge_max)
        
        # Plot gauge background
        for i in range(99):
            ax.fill_between([x[i], x[i+1]], [y[i], y[i+1]], color=cmap(norm(i)))
            
        # Plot the needle
        needle_theta = np.pi * (1 - score / 100)
        needle_x = [0, r * np.cos(needle_theta)]
        needle_y = [0, r * np.sin(needle_theta)]
        ax.plot(needle_x, needle_y, 'k-', linewidth=3)
        ax.add_patch(plt.Circle((0, 0), 0.05, color='k'))
        
        # Add labels
        ax.text(-0.8, -0.2, '0', fontsize=12)
        ax.text(0.8, -0.2, '100', fontsize=12)
        ax.text(0, 0.2, f'Risk Score: {score}%', fontsize=14, ha='center', fontweight='bold')
        
        # Set plot properties
        ax.set_xlim(-1, 1)
        ax.set_ylim(-0.1, 1)
        ax.axis('off')
        
        if output_path:
            plt.savefig(output_path, format='png', dpi=300, bbox_inches='tight')
            plt.close()
            return output_path
        else:
            # Return the figure as bytes
            buf = io.BytesIO()
            plt.savefig(buf, format='png', dpi=300, bbox_inches='tight')
            plt.close()
            buf.seek(0)
            return buf

    @staticmethod
    def create_vulnerability_timeline(vulnerabilities, output_path=None):
        """Create a timeline-like chart showing vulnerability distribution"""
        # Count vulnerabilities by severity
        severity_order = ['Critical', 'High', 'Medium', 'Low', 'Info', 'Unknown']
        severity_counts = {sev: 0 for sev in severity_order}
        
        for vuln in vulnerabilities:
            if vuln.severity in severity_counts:
                severity_counts[vuln.severity] += 1
        
        # Filter out zeros
        severity_counts = {k: v for k, v in severity_counts.items() if v > 0}
        
        # Set colors for different severity levels
        colors = {
            'Critical': '#dc3545',  # Red
            'High': '#fd7e14',      # Orange
            'Medium': '#ffc107',    # Yellow
            'Low': '#28a745',       # Green
            'Info': '#17a2b8',      # Blue
            'Unknown': '#6c757d'    # Gray
        }
        
        # Create horizontal bar chart
        plt.figure(figsize=(8, 4))
        
        # Sort by severity
        sorted_items = [(sev, severity_counts.get(sev, 0)) for sev in severity_order if sev in severity_counts]
        labels = [item[0] for item in sorted_items]
        values = [item[1] for item in sorted_items]
        bar_colors = [colors.get(label, '#6c757d') for label in labels]
        
        y_pos = np.arange(len(labels))
        plt.barh(y_pos, values, color=bar_colors)
        plt.yticks(y_pos, labels)
        
        # Add count labels to the bars
        for i, v in enumerate(values):
            plt.text(v + 0.1, i, str(v), color='black', va='center')
        
        plt.title('Vulnerability Count by Severity')
        plt.tight_layout()
        
        if output_path:
            plt.savefig(output_path, format='png', dpi=300, bbox_inches='tight')
            plt.close()
            return output_path
        else:
            # Return the figure as bytes
            buf = io.BytesIO()
            plt.savefig(buf, format='png', dpi=300, bbox_inches='tight')
            plt.close()
            buf.seek(0)
            return buf


class ReportLabPDFGenerator:
    """Generate PDF reports using ReportLab"""
    def __init__(self, report_data, chart_generator=None, ai_enhancer=None):
        self.report = report_data
        self.chart_generator = chart_generator or ChartGenerator()
        self.ai_enhancer = ai_enhancer
        self.styles = getSampleStyleSheet()
        self.setup_styles()
        
    def setup_styles(self):
        """Set up custom styles"""
        self.styles.add(ParagraphStyle(
            name='Title',
            parent=self.styles['Title'],
            fontSize=24,
            spaceAfter=12,
            textColor=colors.darkblue
        ))
        
        self.styles.add(ParagraphStyle(
            name='Subtitle',
            parent=self.styles['Heading2'],
            fontSize=16,
            spaceAfter=12,
            textColor=colors.darkblue
        ))
        
        self.styles.add(ParagraphStyle(
            name='Heading1',
            parent=self.styles['Heading1'],
            fontSize=18,
            spaceAfter=12,
            textColor=colors.darkblue
        ))
        
        self.styles.add(ParagraphStyle(
            name='Heading2',
            parent=self.styles['Heading2'],
            fontSize=16,
            spaceAfter=10,
            textColor=colors.darkblue
        ))
        
        self.styles.add(ParagraphStyle(
            name='Heading3',
            parent=self.styles['Heading3'],
            fontSize=14,
            spaceAfter=8,
            textColor=colors.darkblue
        ))
        
        self.styles.add(ParagraphStyle(
            name='BodyText',
            parent=self.styles['BodyText'],
            fontSize=11,
            spaceAfter=6
        ))
        
        self.styles.add(ParagraphStyle(
            name='Critical',
            parent=self.styles['BodyText'],
            fontSize=11,
            spaceAfter=6,
            borderPadding=10,
            borderWidth=1,
            borderColor=colors.red,
            borderRadius=5
        ))
        
        self.styles.add(ParagraphStyle(
            name='Confidential',
            parent=self.styles['BodyText'],
            fontSize=10,
            textColor=colors.red,
            backColor=colors.lightgrey,
            borderPadding=5,
            alignment=1  # Center alignment
        ))
    
    def create_header_footer(self, canvas, doc):
        """Add header and footer to each page"""
        # Save canvas state
        canvas.saveState()
        
        # Header
        canvas.setFont('Helvetica-Bold', 10)
        canvas.drawString(inch, 10.5 * inch, self.report.client_name)
        canvas.drawRightString(7.5 * inch, 10.5 * inch, self.report.report_id)
        canvas.line(inch, 10.4 * inch, 7.5 * inch, 10.4 * inch)
        
        # Footer
        canvas.setFont('Helvetica', 8)
        page_num_text = f"Page {doc.page} of {doc.page}"  # Will be updated in onLaterPages
        canvas.drawCentredString(4.25 * inch, 0.75 * inch, page_num_text)
        canvas.line(inch, 0.9 * inch, 7.5 * inch, 0.9 * inch)
        canvas.drawString(inch, 0.75 * inch, "CONFIDENTIAL")
        canvas.drawRightString(7.5 * inch, 0.75 * inch, f"Generated: {self.report.report_date}")
        
        # Release canvas state
        canvas.restoreState()
    
    def later_pages(self, canvas, doc):
        """Define layout for pages after the first one"""
        self.create_header_footer(canvas, doc)
        
    def first_page(self, canvas, doc):
        """Define layout for the first page"""
        self.create_header_footer(canvas, doc)
        
        # Add a logo or company name at the top
        canvas.saveState()
        canvas.setFont('Helvetica-Bold', 24)
        canvas.drawCentredString(4.25 * inch, 9 * inch, self.report.client_name)
        canvas.setFont('Helvetica-Bold', 18)
        canvas.drawCentredString(4.25 * inch, 8.5 * inch, "Vulnerability Assessment &")
        canvas.drawCentredString(4.25 * inch, 8.1 * inch, "Penetration Testing Report")
        canvas.setFont('Helvetica', 12)
        canvas.drawCentredString(4.25 * inch, 7.5 * inch, f"Project: {self.report.project_name}")
        canvas.drawCentredString(4.25 * inch, 7.1 * inch, f"Assessment Date: {self.report.assessment_date}")
        canvas.drawCentredString(4.25 * inch, 6.7 * inch, f"Report Date: {self.report.report_date}")
        if self.report.assessor_name:
            canvas.drawCentredString(4.25 * inch, 6.3 * inch, f"Prepared by: {self.report.assessor_name}")
            
        # Add a border around the page
        canvas.setStrokeColorRGB(0.8, 0.8, 0.8)
        canvas.setLineWidth(1)
        canvas.rect(inch, inch, 6.5 * inch, 9 * inch)
        canvas.restoreState()
    
    def create_toc(self):
        """Create table of contents"""
        elements = []
        elements.append(Paragraph("Table of Contents", self.styles['Heading1']))
        elements.append(Spacer(1, 0.2 * inch))
        
        toc_data = [
            ["1. Executive Summary", "3"],
            ["2. Scope of Assessment", "4"],
            ["3. Methodology", "5"],
            ["4. Summary of Findings", "6"],
            ["5. Detailed Vulnerability Analysis", "7"],
            ["6. Remediation Recommendations", "10"],
            ["7. Conclusion", "12"],
            ["Appendix A: Vulnerability Details", "13"]
        ]
        
        # Create TOC table
        toc_table = Table(toc_data, colWidths=[5*inch, 0.5*inch])
        toc_table.setStyle(TableStyle([
            ('FONT', (0, 0), (-1, -1), 'Helvetica', 11),
            ('TEXTCOLOR', (0, 0), (0, -1), colors.black),
            ('ALIGN', (1, 0), (1, -1), 'RIGHT'),
            ('LINEBELOW', (0, 0), (-1, -2), 0.5, colors.lightgrey),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ]))
        
        elements.append(toc_table)
        elements.append(Spacer(1, 0.5 * inch))
        elements.append(PageBreak())
        
        return elements
        
    def create_executive_summary(self):
        """Create executive summary section"""
        elements = []
        elements.append(Paragraph("1. Executive Summary", self.styles['Heading1']))
        elements.append(Spacer(1, 0.1 * inch))
        
        # Use AI-enhanced summary if available
        summary_text = self.report.executive_summary
        if self.ai_enhancer and self.ai_enhancer.is_available():
            enhanced_summary = self.ai_enhancer.enhance_executive_summary(self.report)
            if enhanced_summary and len(enhanced_summary) > len(summary_text):
                summary_text = enhanced_summary
        
        # Split the summary into paragraphs
        summary_paragraphs = summary_text.split('\n\n')
        for para in summary_paragraphs:
            if para.strip():
                elements.append(Paragraph(para.strip(), self.styles['BodyText']))
                elements.append(Spacer(1, 0.1 * inch))
        
        elements.append(Spacer(1, 0.2 * inch))
        
        # Add severity distribution chart
        if 'statistics' in self.report.custom_fields:
            elements.append(Paragraph("Vulnerability Severity Distribution", self.styles['Heading3']))
            
            # Generate chart
            chart_buffer = self.chart_generator.create_severity_pie_chart(
                self.report.custom_fields['statistics']
            )
            
            # Add chart to document
            img = RLImage(chart_buffer, width=5*inch, height=3*inch)
            elements.append(img)
            elements.append(Spacer(1, 0.3 * inch))
            
            # Add risk score gauge
            if 'risk_score' in self.report.custom_fields:
                elements.append(Paragraph("Overall Risk Assessment", self.styles['Heading3']))
                
                # Generate risk gauge
                gauge_buffer = self.chart_generator.create_risk_score_gauge(
                    self.report.custom_fields['risk_score']
                )
                
                # Add gauge to document
                img = RLImage(gauge_buffer, width=5*inch, height=2.5*inch)
                elements.append(img)
        
        elements.append(Spacer(1, 0.2 * inch))
        elements.append(PageBreak())
        
        return elements
        
    def create_scope_section(self):
        """Create scope section"""
        elements = []
        elements.append(Paragraph("2. Scope of Assessment", self.styles['Heading1']))
        elements.append(Spacer(1, 0.1 * inch))
        
        elements.append(Paragraph("The following systems and applications were included in the assessment:", self.styles['BodyText']))
        elements.append(Spacer(1, 0.1 * inch))
        
        # Create a bulletted list of scope items
        for item in self.report.scope:
            bullet_item = f"• {item}"
            elements.append(Paragraph(bullet_item, self.styles['BodyText']))
            elements.append(Spacer(1, 0.05 * inch))
        
        elements.append(Spacer(1, 0.2 * inch))
        elements.append(PageBreak())
        
        return elements
        
    def create_methodology_section(self):
        """Create methodology section"""
        elements = []
        elements.append(Paragraph("3. Methodology", self.styles['Heading1']))
        elements.append(Spacer(1, 0.1 * inch))
        
        elements.append(Paragraph("The assessment followed industry-standard methodologies including steps from OWASP, NIST, and PTES frameworks:", self.styles['BodyText']))
        elements.append(Spacer(1, 0.1 * inch))
        
        # Create a numbered list of methodology steps
        for i, step in enumerate(self.report.methodology, 1):
            numbered_item = f"{i}. {step}"
            elements.append(Paragraph(numbered_item, self.styles['BodyText']))
            elements.append(Spacer(1, 0.05 * inch))
        
        elements.append(Spacer(1, 0.3 * inch))
        elements.append(PageBreak())
        
        return elements
        
    def create_findings_summary(self):
        """Create summary of findings section"""
        elements = []
        elements.append(Paragraph("4. Summary of Findings", self.styles['Heading1']))
        elements.append(Spacer(1, 0.1 * inch))
        
        # Create vulnerability bar chart
        chart_buffer = self.chart_generator.create_vulnerability_timeline(
            self.report.vulnerabilities
        )
        
        # Add chart to document
        img = RLImage(chart_buffer, width=6*inch, height=3*inch)
        elements.append(img)
        elements.append(Spacer(1, 0.2 * inch))
        
        # Create table with summary of vulnerabilities
        elements.append(Paragraph("Vulnerability Overview", self.styles['Heading2']))
        elements.append(Spacer(1, 0.1 * inch))
        
        # Table header and data
        data = [["#", "Title", "Severity", "CVSS", "Status"]]
        
        # Fill the table with vulnerability data
        for i, vuln in enumerate(self.report.vulnerabilities, 1):
            data.append([
                str(i),
                vuln.title,
                vuln.severity,
                str(vuln.cvss_score),
                vuln.status
                        ])
        
        # Create the table
        table = Table(data, colWidths=[0.5*inch, 3.5*inch, 1*inch, 1*inch, 1*inch])
        table.setStyle(TableStyle([
            ('FONT', (0, 0), (-1, -1), 'Helvetica', 10),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.lightgrey),
            ('BACKGROUND', (0, 0), (-1, 0), colors.lightblue),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ]))
        
        elements.append(table)
        elements.append(Spacer(1, 0.3 * inch))
        elements.append(PageBreak())
        
        return elements
        
    def create_vulnerability_analysis(self):
        """Create detailed vulnerability analysis section"""
        elements = []
        elements.append(Paragraph("5. Detailed Vulnerability Analysis", self.styles['Heading1']))
        elements.append(Spacer(1, 0.1 * inch))
        
        # Iterate through vulnerabilities and add details
        for i, vuln in enumerate(self.report.vulnerabilities, 1):
            elements.append(Paragraph(f"{i}. {vuln.title}", self.styles['Heading2']))
            elements.append(Spacer(1, 0.05 * inch))
            
            # Add severity and CVSS score
            severity_text = f"<b>Severity:</b> {vuln.severity}"
            cvss_text = f"<b>CVSS Score:</b> {vuln.cvss_score}"
            elements.append(Paragraph(severity_text, self.styles['BodyText']))
            elements.append(Paragraph(cvss_text, self.styles['BodyText']))
            elements.append(Spacer(1, 0.05 * inch))
            
            # Add description
            elements.append(Paragraph("<b>Description:</b>", self.styles['BodyText']))
            elements.append(Paragraph(vuln.description, self.styles['BodyText']))
            elements.append(Spacer(1, 0.05 * inch))
            
            # Add impact
            elements.append(Paragraph("<b>Impact:</b>", self.styles['BodyText']))
            elements.append(Paragraph(vuln.impact, self.styles['BodyText']))
            elements.append(Spacer(1, 0.05 * inch))
            
            # Add remediation
            elements.append(Paragraph("<b>Remediation:</b>", self.styles['BodyText']))
            elements.append(Paragraph(vuln.remediation, self.styles['BodyText']))
            elements.append(Spacer(1, 0.05 * inch))
            
            # Add affected components
            if vuln.affected_components:
                elements.append(Paragraph("<b>Affected Components:</b>", self.styles['BodyText']))
                for component in vuln.affected_components:
                    elements.append(Paragraph(f"• {component}", self.styles['BodyText']))
                elements.append(Spacer(1, 0.05 * inch))
            
            # Add proof of concept
            if vuln.proof_of_concept:
                elements.append(Paragraph("<b>Proof of Concept:</b>", self.styles['BodyText']))
                elements.append(Paragraph(vuln.proof_of_concept, self.styles['BodyText']))
                elements.append(Spacer(1, 0.05 * inch))
            
            # Add references
            if vuln.references:
                elements.append(Paragraph("<b>References:</b>", self.styles['BodyText']))
                for ref in vuln.references:
                    elements.append(Paragraph(f"• {ref}", self.styles['BodyText']))
                elements.append(Spacer(1, 0.05 * inch))
            
            elements.append(Spacer(1, 0.2 * inch))
        
        elements.append(PageBreak())
        return elements
        
    def create_remediation_recommendations(self):
        """Create remediation recommendations section"""
        elements = []
        elements.append(Paragraph("6. Remediation Recommendations", self.styles['Heading1']))
        elements.append(Spacer(1, 0.1 * inch))
        
        # Use AI-generated checklist if available
        if self.ai_enhancer and self.ai_enhancer.is_available():
            checklist = self.ai_enhancer.generate_remediation_checklist(self.report.vulnerabilities)
            if checklist:
                elements.append(Paragraph("The following checklist provides actionable steps for remediation:", self.styles['BodyText']))
                elements.append(Spacer(1, 0.1 * inch))
                
                for component, actions in checklist.items():
                    elements.append(Paragraph(f"<b>{component}:</b>", self.styles['BodyText']))
                    for action in actions:
                        elements.append(Paragraph(f"• {action}", self.styles['BodyText']))
                    elements.append(Spacer(1, 0.05 * inch))
                
                elements.append(Spacer(1, 0.2 * inch))
        
        # Add prioritized roadmap if available
        if self.ai_enhancer and self.ai_enhancer.is_available():
            roadmap = self.ai_enhancer.prioritize_recommendations(self.report.vulnerabilities)
            if roadmap:
                elements.append(Paragraph("Prioritized Remediation Roadmap:", self.styles['BodyText']))
                elements.append(Spacer(1, 0.1 * inch))
                
                for timeframe, actions in roadmap.items():
                    elements.append(Paragraph(f"<b>{timeframe}:</b>", self.styles['BodyText']))
                    for action in actions:
                        elements.append(Paragraph(f"• {action}", self.styles['BodyText']))
                    elements.append(Spacer(1, 0.05 * inch))
                
                elements.append(Spacer(1, 0.2 * inch))
        
        elements.append(PageBreak())
        return elements
        
    def create_conclusion(self):
        """Create conclusion section"""
        elements = []
        elements.append(Paragraph("7. Conclusion", self.styles['Heading1']))
        elements.append(Spacer(1, 0.1 * inch))
        
        conclusion_text = """
        This report summarizes the findings of the vulnerability assessment and penetration testing conducted on the target systems. 
        The identified vulnerabilities have been categorized by severity, and remediation recommendations have been provided. 
        It is recommended that the client prioritize the remediation of critical and high-severity vulnerabilities to mitigate potential risks.
        """
        
        elements.append(Paragraph(conclusion_text, self.styles['BodyText']))
        elements.append(Spacer(1, 0.2 * inch))
        elements.append(PageBreak())
        
        return elements
        
    def create_appendix(self):
        """Create appendix section"""
        elements = []
        elements.append(Paragraph("Appendix A: Vulnerability Details", self.styles['Heading1']))
        elements.append(Spacer(1, 0.1 * inch))
        
        # Add a table with all vulnerabilities
        data = [["#", "Title", "Severity", "CVSS", "Status"]]
        for i, vuln in enumerate(self.report.vulnerabilities, 1):
            data.append([
                str(i),
                vuln.title,
                vuln.severity,
                str(vuln.cvss_score),
                vuln.status
            ])
        
        table = Table(data, colWidths=[0.5*inch, 3.5*inch, 1*inch, 1*inch, 1*inch])
        table.setStyle(TableStyle([
            ('FONT', (0, 0), (-1, -1), 'Helvetica', 10),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.lightgrey),
            ('BACKGROUND', (0, 0), (-1, 0), colors.lightblue),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ]))
        
        elements.append(table)
        return elements
        
    def generate_pdf(self, output_path):
        """Generate the full PDF report"""
        # Create the PDF document
        doc = SimpleDocTemplate(
            output_path,
            pagesize=A4,
            leftMargin=inch,
            rightMargin=inch,
            topMargin=inch,
            bottomMargin=inch
        )
        
        # Build the document content
        elements = []
        elements.extend(self.create_toc())
        elements.extend(self.create_executive_summary())
        elements.extend(self.create_scope_section())
        elements.extend(self.create_methodology_section())
        elements.extend(self.create_findings_summary())
        elements.extend(self.create_vulnerability_analysis())
        elements.extend(self.create_remediation_recommendations())
        elements.extend(self.create_conclusion())
        elements.extend(self.create_appendix())
        
        # Build the PDF
        doc.build(elements, onFirstPage=self.first_page, onLaterPages=self.later_pages)


def main():
    # Example usage
    vulnerabilities = [
        Vulnerability(
            title="SQL Injection",
            severity="High",
            description="A SQL injection vulnerability was found in the login form.",
            impact="Attackers can execute arbitrary SQL queries.",
            remediation="Use parameterized queries.",
            cvss_score=8.5,
            affected_components=["Web Application"],
            proof_of_concept="Payload: ' OR '1'='1",
            references=["https://owasp.org/www-community/attacks/SQL_Injection"]
        ),
        Vulnerability(
            title="Cross-Site Scripting (XSS)",
            severity="Medium",
            description="A reflected XSS vulnerability was detected in the search functionality.",
            impact="Attackers can execute arbitrary JavaScript in the victim's browser.",
            remediation="Sanitize user inputs.",
            cvss_score=6.5,
            affected_components=["Web Application"],
            proof_of_concept="Payload: <script>alert('XSS')</script>",
            references=["https://owasp.org/www-community/attacks/xss/"]
        )
    ]
    
    report = VAPTReport(
        project_name="Example Project",
        client_name="Example Client",
        assessment_date="2023-10-01",
        scope=["Web Application", "API Endpoints"],
        methodology=["Reconnaissance", "Vulnerability Scanning", "Manual Testing"],
        executive_summary="This report summarizes the findings of the vulnerability assessment.",
        vulnerabilities=vulnerabilities,
        custom_fields={
            "statistics": {
                "Critical": 0,
                "High": 1,
                "Medium": 1,
                "Low": 0,
                "Info": 0,
                "Unknown": 0
            },
            "risk_score": 75
        }
    )
    
    # Generate the PDF
    pdf_generator = ReportLabPDFGenerator(report)
    pdf_generator.generate_pdf("vapt_report.pdf")
    print("Report generated successfully!")


if __name__ == "__main__":
    main()