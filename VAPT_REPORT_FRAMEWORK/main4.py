import os
import json
import csv
import argparse
import tempfile
import shutil
from datetime import datetime
from pathlib import Path
import requests
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
import base64
from jinja2 import Environment, FileSystemLoader
import pandas as pd
import markdown
import pdfkit
import matplotlib.pyplot as plt
import matplotlib
matplotlib.use('Agg')  # Use non-interactive backend
import seaborn as sns
import numpy as np


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
    """Class to enhance reports using AI capabilities"""
    
    def __init__(self, api_key=None):
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY")
        if not self.api_key:
            print("Warning: No API key provided for AI enhancement. Some features will be limited.")
    
    def enhance_executive_summary(self, report: VAPTReport) -> str:
        """Use AI to enhance the executive summary with more professional language"""
        if not self.api_key:
            return report.executive_summary
            
        try:
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}"
            }
            
            # Create statistics info for the AI
            stats = report.custom_fields.get('statistics', {})
            stats_text = "\n".join([f"{severity}: {count}" for severity, count in stats.items() if count > 0])
            
            # Create a prompt for the AI
            prompt = f"""You are a cybersecurity expert writing a professional VAPT report. 
            Enhance the following executive summary to make it more professional and comprehensive.
            
            Original summary: {report.executive_summary}
            
            Assessment scope: {', '.join(report.scope)}
            
            Vulnerability statistics: 
            {stats_text}
            
            Please improve this executive summary to be more professional, including key insights about the security posture,
            high-level risk assessment, and recommendations. Keep the tone formal and authoritative. 
            Do not use placeholder text or mention that this is an AI-generated response.
            """
            
            payload = {
                "model": "gpt-3.5-turbo",
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.7,
                "max_tokens": 1000
            }
            
            response = requests.post(
                "https://api.openai.com/v1/chat/completions",
                headers=headers,
                json=payload
            )
            
            if response.status_code == 200:
                return response.json()["choices"][0]["message"]["content"]
            else:
                print(f"Error enhancing executive summary: {response.text}")
                return report.executive_summary
                
        except Exception as e:
            print(f"Error using AI enhancer: {e}")
            return report.executive_summary
    
    def generate_remediation_steps(self, vulnerability: Vulnerability) -> str:
        """Use AI to generate more detailed remediation steps"""
        if not self.api_key:
            return vulnerability.remediation
            
        try:
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}"
            }
            
            prompt = f"""You are a cybersecurity expert providing detailed remediation steps for a vulnerability.
            
            Vulnerability: {vulnerability.title}
            Severity: {vulnerability.severity}
            Description: {vulnerability.description}
            Current remediation advice: {vulnerability.remediation}
            
            Please provide a more detailed, step-by-step remediation plan for this vulnerability.
            Include specific actions, code examples if relevant, and best practices.
            Format your response as a bulleted list with clear, actionable steps.
            """
            
            payload = {
                "model": "gpt-3.5-turbo",
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.7,
                "max_tokens": 1000
            }
            
            response = requests.post(
                "https://api.openai.com/v1/chat/completions",
                headers=headers,
                json=payload
            )
            
            if response.status_code == 200:
                enhanced_remediation = response.json()["choices"][0]["message"]["content"]
                return enhanced_remediation
            else:
                print(f"Error generating remediation steps: {response.text}")
                return vulnerability.remediation
                
        except Exception as e:
            print(f"Error using AI enhancer: {e}")
            return vulnerability.remediation


class VAPTReportGenerator:
    def __init__(self, template_dir="templates", use_ai=False, api_key=None):
        self.template_dir = template_dir
        self.env = Environment(loader=FileSystemLoader(template_dir))
        self.parsers = {
            'json': JSONParser(),
            'csv': CSVParser(),
            'nessus': NessusParser()
        }
        self.use_ai = use_ai
        self.ai_enhancer = AIEnhancer(api_key) if use_ai else None
    
    def load_report_metadata(self, metadata_file):
        """Load basic report information from a JSON file"""
        with open(metadata_file, 'r') as f:
            metadata = json.load(f)
        
        return VAPTReport(
            project_name=metadata.get('project_name', 'Unnamed Project'),
            client_name=metadata.get('client_name', 'Unnamed Client'),
            assessment_date=metadata.get('assessment_date', datetime.now().strftime("%Y-%m-%d")),
            scope=metadata.get('scope', []),
            methodology=metadata.get('methodology', []),
            executive_summary=metadata.get('executive_summary', ''),
            vulnerabilities=[],  # Will be populated later
            assessor_name=metadata.get('assessor_name', ''),
            report_id=metadata.get('report_id', f"VAPT-{datetime.now().strftime('%Y%m%d')}"),
            confidentiality_statement=metadata.get('confidentiality_statement', ''),
            custom_fields=metadata.get('custom_fields', {})
        )
    
    def parse_vulnerability_data(self, file_path, format_type):
        """Parse vulnerability data from file using the appropriate parser"""
        if format_type not in self.parsers:
            raise ValueError(f"Unsupported format type: {format_type}")
        
        return self.parsers[format_type].parse(file_path)
    
    def generate_charts(self, report, output_dir):
        """Generate charts and graphs for the report"""
        stats = report.custom_fields['statistics']
        chart_files = {}
        
        # Create a temporary directory for the charts
        os.makedirs(output_dir, exist_ok=True)
        
        # Generate severity distribution pie chart
        plt.figure(figsize=(8, 6))
        labels = []
        sizes = []
        colors = []
        color_map = {
            'Critical': '#dc3545',
            'High': '#fd7e14',
            'Medium': '#ffc107',
            'Low': '#28a745',
            'Info': '#17a2b8',
            'Unknown': '#6c757d'
        }
        explode = []
        
        for severity, count in stats.items():
            if count > 0:
                labels.append(f"{severity} ({count})")
                sizes.append(count)
                colors.append(color_map.get(severity, '#6c757d'))
                # Explode the critical and high slices
                explode.append(0.1 if severity in ['Critical', 'High'] else 0)
        
        plt.pie(sizes, explode=explode, labels=labels, colors=colors, autopct='%1.1f%%', 
                shadow=True, startangle=140, wedgeprops={'edgecolor': 'white'})
        plt.axis('equal')
        plt.title('Vulnerability Severity Distribution')
        pie_chart_path = os.path.join(output_dir, 'severity_distribution.png')
        plt.savefig(pie_chart_path, dpi=300, bbox_inches='tight')
        plt.close()
        chart_files['severity_pie'] = pie_chart_path
        
        # Generate severity bar chart
        plt.figure(figsize=(10, 6))
        severities = ['Critical', 'High', 'Medium', 'Low', 'Info']
        counts = [stats.get(sev, 0) for sev in severities]
        bar_colors = [color_map.get(sev, '#6c757d') for sev in severities]
        
        bars = plt.bar(severities, counts, color=bar_colors)
        plt.xlabel('Severity')
        plt.ylabel('Number of Vulnerabilities')
        plt.title('Vulnerability Counts by Severity')
        for bar in bars:
            height = bar.get_height()
            plt.text(bar.get_x() + bar.get_width()/2., height + 0.1,
                    '%d' % int(height), ha='center', va='bottom')
        
        bar_chart_path = os.path.join(output_dir, 'severity_counts.png')
        plt.savefig(bar_chart_path, dpi=300, bbox_inches='tight')
        plt.close()
        chart_files['severity_bar'] = bar_chart_path
        
        # Generate risk radar chart if we have enough data
        if len(report.vulnerabilities) >= 3:
            categories = ['Authentication', 'Authorization', 'Input Validation', 
                        'Configuration', 'Encryption', 'Session Management']
            
            # This is a simplified example - in a real system, you'd categorize actual findings
            # For this demo, we'll create pseudo-random scores based on the vulnerability data
            np.random.seed(42)  # For reproducible results
            values = np.random.randint(1, 10, size=len(categories))
            
            # Adjust based on actual findings
            if any('Authentication' in v.title or 'Login' in v.title for v in report.vulnerabilities):
                values[0] = max(values[0], 7)
            if any('Authorization' in v.title or 'Permission' in v.title for v in report.vulnerabilities):
                values[1] = max(values[1], 7)
            if any('Injection' in v.title or 'XSS' in v.title for v in report.vulnerabilities):
                values[2] = max(values[2], 8)
            if any('Configuration' in v.title or 'Header' in v.title for v in report.vulnerabilities):
                values[3] = max(values[3], 6)
            if any('Encryption' in v.title or 'SSL' in v.title for v in report.vulnerabilities):
                values[4] = max(values[4], 7)
            if any('Session' in v.title or 'Cookie' in v.title for v in report.vulnerabilities):
                values[5] = max(values[5], 7)
            
            # Close the loop for the radar chart
            values = np.append(values, values[0])
            categories = np.append(categories, categories[0])
            
            # Create the radar chart
            plt.figure(figsize=(8, 8))
            theta = np.linspace(0, 2*np.pi, len(categories))
            
            plt.polar(theta, values)
            plt.fill(theta, values, 'b', alpha=0.1)
            
            plt.xticks(theta[:-1], categories[:-1])
            plt.yticks([2, 4, 6, 8], ['2', '4', '6', '8'], color='grey', size=8)
            plt.ylim(0, 10)
            
            plt.title('Security Risk Assessment by Category')
            radar_chart_path = os.path.join(output_dir, 'risk_radar.png')
            plt.savefig(radar_chart_path, dpi=300, bbox_inches='tight')
            plt.close()
            chart_files['risk_radar'] = radar_chart_path
        
        return chart_files
    
    def create_cvss_visualization(self, score, output_path):
        """Create a CVSS score visualization"""
        plt.figure(figsize=(8, 2))
        
        # Define color gradient
        if score >= 9.0:
            color = '#dc3545'  # Critical - Red
        elif score >= 7.0:
            color = '#fd7e14'  # High - Orange
        elif score >= 4.0:
            color = '#ffc107'  # Medium - Yellow
        else:
            color = '#28a745'  # Low - Green
        
        # Create a horizontal bar
        plt.barh(0, score, height=0.5, color=color)
        plt.barh(0, 10, height=0.5, color='#e9ecef', alpha=0.3)
        
        # Add the score text
        plt.text(score/2, 0, f"{score}", ha='center', va='center', color='white', fontweight='bold')
        
        # Set labels and limits
        plt.xlim(0, 10)
        plt.yticks([])
        plt.xticks([0, 2, 4, 6, 8, 10])
        plt.xlabel('CVSS Score')
        plt.title('CVSS Score Visualization')
        
        # Add severity labels
        plt.axvline(x=4, color='gray', linestyle='--', alpha=0.3)
        plt.axvline(x=7, color='gray', linestyle='--', alpha=0.3)
        plt.axvline(x=9, color='gray', linestyle='--', alpha=0.3)
        
        plt.text(2, -0.5, 'Low', ha='center', va='top')
        plt.text(5.5, -0.5, 'Medium', ha='center', va='top')
        plt.text(8, -0.5, 'High', ha='center', va='top')
        plt.text(9.5, -0.5, 'Critical', ha='center', va='top')
        
        plt.savefig(output_path, dpi=200, bbox_inches='tight')
        plt.close()
        
        return output_path
    
    def generate_cvss_visualizations(self, report, output_dir):
        """Generate CVSS visualizations for each vulnerability"""
        cvss_charts = {}
        
        for i, vuln in enumerate(report.vulnerabilities):
            if vuln.cvss_score > 0:
                chart_path = os.path.join(output_dir, f'cvss_{i+1}.png')
                self.create_cvss_visualization(vuln.cvss_score, chart_path)
                cvss_charts[i+1] = chart_path
        
        return cvss_charts
    
    def generate_report(self, report_data, template_name, output_format='pdf', output_file=None, temp_dir=None):
        """Generate report using the specified template and output format"""
        # Create a temporary directory for assets if not provided
        if not temp_dir:
            temp_dir = tempfile.mkdtemp()
        
        # AI enhancement if enabled
        if self.use_ai and self.ai_enhancer:
            print("Enhancing report with AI...")
            # Enhance executive summary
            report_data.executive_summary = self.ai_enhancer.enhance_executive_summary(report_data)
            
            # Enhance remediation steps for each vulnerability
            for vuln in report_data.vulnerabilities:
                if vuln.remediation:
                    vuln.remediation = self.ai_enhancer.generate_remediation_steps(vuln)
        
        # Generate charts
        charts_dir = os.path.join(temp_dir, 'charts')
        os.makedirs(charts_dir, exist_ok=True)
        
        print("Generating charts and visualizations...")
        chart_files = self.generate_charts(report_data, charts_dir)
        cvss_charts = self.generate_cvss_visualizations(report_data, charts_dir)
        
        # Add chart paths to the report data
        report_data.custom_fields['charts'] = chart_files
        report_data.custom_fields['cvss_charts'] = cvss_charts
        
        # Prepare output file
        if output_file is None:
            output_file = f"{report_data.project_name.replace(' ', '_')}_{datetime.now().strftime('%Y%m%d')}"
        
        if not output_file.endswith(f".{output_format}"):
            output_file = f"{output_file}.{output_format}"
        
        # Generate HTML first, regardless of final output format
        template = self.env.get_template(f"{template_name}.html.jinja")
        rendered_content = template.render(report=report_data)
        
        html_file = os.path.join(temp_dir, 'report.html')
        with open(html_file, 'w') as f:
            f.write(rendered_content)
        
        final_output = output_file
        
        if output_format == 'html':
            # Just copy the HTML file to the final destination
            shutil.copy(html_file, output_file)
        
        elif output_format == 'pdf':
            print(f"Generating PDF report: {output_file}")
            try:
                # Use pdfkit for PDF generation
                options = {
                    'page-size': 'A4',
                    'margin-top': '20mm',
                    'margin-right': '20mm',
                    'margin-bottom': '20mm',
                    'margin-left': '20mm',
                    'encoding': 'UTF-8',
                    'no-outline': None,
                    'enable-local-file-access': None
                }
                pdfkit.from_file(html_file, output_file, options=options)
                print(f"PDF generated using pdfkit: {output_file}")
            except Exception as e:
                print(f"Error with pdfkit: {e}")
                print("Could not generate PDF, saving HTML instead")
                shutil.copy(html_file, output_file.replace('.pdf', '.html'))
                final_output = output_file.replace('.pdf', '.html')
        
        # Clean up temporary directory
        # Uncomment if you want to clean up the temp files 
        # shutil.rmtree(temp_dir)
        
        return final_output
    
    def categorize_vulnerabilities(self, vulnerabilities):
        """Categorize vulnerabilities by severity for statistics"""
        categories = {
            'Critical': 0,
            'High': 0,
            'Medium': 0,
            'Low': 0,
            'Info': 0,
            'Unknown': 0
        }
        
        for vuln in vulnerabilities:
            if vuln.severity in categories:
                categories[vuln.severity] += 1
            else:
                categories['Unknown'] += 1
        
        return categories
    
    def add_statistics(self, report):
        """Add vulnerability statistics to report"""
        stats = self.categorize_vulnerabilities(report.vulnerabilities)
        report.custom_fields['statistics'] = stats
        report.custom_fields['total_vulnerabilities'] = len(report.vulnerabilities)
        
        # Calculate risk score (example method - customize as needed)
        risk_weights = {
            'Critical': 10,
            'High': 7,
            'Medium': 4,
            'Low': 1,
            'Info': 0,
            'Unknown': 2
        }
        
        weighted_sum = sum(stats[sev] * risk_weights[sev] for sev in stats)
        max_possible = sum(risk_weights[sev] * len(report.vulnerabilities) for sev in risk_weights) / len(risk_weights)
        
        if max_possible > 0:
            risk_percentage = (weighted_sum / max_possible) * 100
        else:
            risk_percentage = 0
            
        report.custom_fields['risk_score'] = round(risk_percentage, 1)
        
        # Add risk level text
        if risk_percentage >= 80:
            report.custom_fields['risk_level'] = "Critical"
            report.custom_fields['risk_color'] = "#dc3545"
        elif risk_percentage >= 60:
            report.custom_fields['risk_level'] = "High"
            report.custom_fields['risk_color'] = "#fd7e14"
        elif risk_percentage >= 40:
            report.custom_fields['risk_level'] = "Medium"
            report.custom_fields['risk_color'] = "#ffc107"
        elif risk_percentage >= 20:
            report.custom_fields['risk_level'] = "Low"
            report.custom_fields['risk_color'] = "#28a745"
        else:
            report.custom_fields['risk_level'] = "Minimal"
            report.custom_fields['risk_color'] = "#17a2b8"
            
        return report


def main():
    parser = argparse.ArgumentParser(description='Enhanced VAPT Report Generator')
    parser.add_argument('--metadata', required=True, help='Path to report metadata JSON file')
    parser.add_argument('--data', required=True, help='Path to vulnerability data file')
    parser.add_argument('--format', required=True, choices=['json', 'csv', 'nessus'], help='Format of vulnerability data')
    parser.add_argument('--template', default='professional', help='Template name to use')
    parser.add_argument('--output-format', default='pdf', choices=['html', 'pdf'], help='Output format')
    parser.add_argument('--output', help='Output file name')
    parser.add_argument('--template-dir', default='templates', help='Directory containing templates')
    parser.add_argument('--use-ai', action='store_true', help='Use AI enhancement for the report')
    parser.add_argument('--api-key', help='API key for AI services (can also be set via OPENAI_API_KEY env var)')
    
    args = parser.parse_args()
    
    print(f"Generating enhanced VAPT report from {args.data}...")
    
    # Create temp directory for report assets
    temp_dir = tempfile.mkdtemp()
    print(f"Created temporary directory: {temp_dir}")
    
    generator = VAPTReportGenerator(
        template_dir=args.template_dir,
        use_ai=args.use_ai,
        api_key=args.api_key
    )
    
    report = generator.load_report_metadata(args.metadata)
    vulnerabilities = generator.parse_vulnerability_data(args.data, args.format)
    report.vulnerabilities = vulnerabilities
    report = generator.add_statistics(report)
    
    output_file = generator.generate_report(
        report_data=report,
        template_name=args.template,
        output_format=args.output_format,
        output_file=args.output,
        temp_dir=temp_dir
    )
    
    print(f"Enhanced report generated: {output_file}")
    print(f"Temporary files are in: {temp_dir}")


if __name__ == "__main__":
    main()