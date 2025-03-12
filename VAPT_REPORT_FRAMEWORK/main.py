import os
import json
import csv
import argparse
from datetime import datetime
from jinja2 import Environment, FileSystemLoader
import pandas as pd
import markdown
import pdfkit
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional


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


class VAPTReportGenerator:
    def __init__(self, template_dir="templates"):
        self.template_dir = template_dir
        self.env = Environment(loader=FileSystemLoader(template_dir))
        self.parsers = {
            'json': JSONParser(),
            'csv': CSVParser(),
            'nessus': NessusParser()
        }
    
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
    
    def generate_report(self, report_data, template_name, output_format='html', output_file=None):
        """Generate report using the specified template and output format"""
        template = self.env.get_template(f"{template_name}.{output_format}.jinja")
        rendered_content = template.render(report=report_data)
        
        if output_file is None:
            output_file = f"{report_data.project_name.replace(' ', '_')}_{datetime.now().strftime('%Y%m%d')}"
        
        if not output_file.endswith(f".{output_format}"):
            output_file = f"{output_file}.{output_format}"
        
        with open(output_file, 'w') as f:
            f.write(rendered_content)
        
        # If PDF output is requested and HTML was generated, convert HTML to PDF
        if output_format == 'html' and output_file.endswith('.pdf'):
            html_file = output_file.replace('.pdf', '.html')
            with open(html_file, 'w') as f:
                f.write(rendered_content)
            
            try:
                pdfkit.from_file(html_file, output_file)
                os.remove(html_file)  # Remove temporary HTML file
            except Exception as e:
                print(f"Error converting to PDF: {e}")
                print("Make sure wkhtmltopdf is installed on your system")
        
        return output_file
    
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
        return report


def main():
    parser = argparse.ArgumentParser(description='VAPT Report Generator')
    parser.add_argument('--metadata', required=True, help='Path to report metadata JSON file')
    parser.add_argument('--data', required=True, help='Path to vulnerability data file')
    parser.add_argument('--format', required=True, choices=['json', 'csv', 'nessus'], help='Format of vulnerability data')
    parser.add_argument('--template', default='default', help='Template name to use')
    parser.add_argument('--output-format', default='html', choices=['html', 'pdf', 'md'], help='Output format')
    parser.add_argument('--output', help='Output file name')
    parser.add_argument('--template-dir', default='templates', help='Directory containing templates')
    
    args = parser.parse_args()
    
    generator = VAPTReportGenerator(template_dir=args.template_dir)
    report = generator.load_report_metadata(args.metadata)
    vulnerabilities = generator.parse_vulnerability_data(args.data, args.format)
    report.vulnerabilities = vulnerabilities
    report = generator.add_statistics(report)
    
    output_file = generator.generate_report(
        report_data=report,
        template_name=args.template,
        output_format=args.output_format,
        output_file=args.output
    )
    
    print(f"Report generated: {output_file}")


if __name__ == "__main__":
    main()
