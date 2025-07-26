#!/usr/bin/env python3
"""
VulnHunter User Manual PDF Generator
Converts the markdown user manual to a professional PDF format
"""

import os
import markdown
from weasyprint import HTML, CSS
from datetime import datetime

def generate_pdf_manual():
    """Generate professional PDF user manual from markdown"""
    
    # Read the markdown content
    try:
        with open('VulnHunter_User_Manual.md', 'r', encoding='utf-8') as f:
            markdown_content = f.read()
    except FileNotFoundError:
        print("Error: VulnHunter_User_Manual.md not found")
        return False
    
    # Convert markdown to HTML
    md = markdown.Markdown(extensions=['tables', 'toc', 'codehilite', 'fenced_code'])
    html_content = md.convert(markdown_content)
    
    # Professional CSS styling for PDF
    css_styles = """
    @page {
        size: A4;
        margin: 2cm 1.5cm 2cm 1.5cm;
        @top-left {
            content: "VulnHunter User Manual";
            font-size: 10px;
            color: #666;
        }
        @top-right {
            content: "Page " counter(page);
            font-size: 10px;
            color: #666;
        }
        @bottom-center {
            content: "Confidential - Internal Use Only";
            font-size: 8px;
            color: #999;
        }
    }
    
    body {
        font-family: 'Arial', 'Helvetica', sans-serif;
        font-size: 11px;
        line-height: 1.6;
        color: #333;
        max-width: none;
        margin: 0;
        padding: 0;
    }
    
    h1 {
        color: #2c3e50;
        font-size: 24px;
        margin-top: 30px;
        margin-bottom: 20px;
        border-bottom: 3px solid #e74c3c;
        padding-bottom: 10px;
        page-break-before: always;
    }
    
    h1:first-child {
        page-break-before: auto;
    }
    
    h2 {
        color: #34495e;
        font-size: 18px;
        margin-top: 25px;
        margin-bottom: 15px;
        border-bottom: 2px solid #3498db;
        padding-bottom: 5px;
    }
    
    h3 {
        color: #2c3e50;
        font-size: 14px;
        margin-top: 20px;
        margin-bottom: 10px;
        font-weight: bold;
    }
    
    h4 {
        color: #34495e;
        font-size: 12px;
        margin-top: 15px;
        margin-bottom: 8px;
        font-weight: bold;
    }
    
    p {
        margin-bottom: 10px;
        text-align: justify;
    }
    
    ul, ol {
        margin-bottom: 15px;
        padding-left: 20px;
    }
    
    li {
        margin-bottom: 5px;
    }
    
    code {
        background-color: #f8f9fa;
        border: 1px solid #e9ecef;
        border-radius: 3px;
        padding: 2px 4px;
        font-family: 'Courier New', monospace;
        font-size: 10px;
    }
    
    pre {
        background-color: #f8f9fa;
        border: 1px solid #e9ecef;
        border-radius: 5px;
        padding: 15px;
        margin: 15px 0;
        font-family: 'Courier New', monospace;
        font-size: 9px;
        overflow-x: auto;
        line-height: 1.4;
    }
    
    pre code {
        background-color: transparent;
        border: none;
        padding: 0;
        font-size: 9px;
    }
    
    table {
        border-collapse: collapse;
        width: 100%;
        margin: 15px 0;
        font-size: 10px;
    }
    
    th, td {
        border: 1px solid #ddd;
        padding: 8px;
        text-align: left;
    }
    
    th {
        background-color: #f2f2f2;
        font-weight: bold;
        color: #2c3e50;
    }
    
    tr:nth-child(even) {
        background-color: #f9f9f9;
    }
    
    blockquote {
        border-left: 4px solid #3498db;
        margin: 15px 0;
        padding-left: 15px;
        color: #555;
        font-style: italic;
    }
    
    .warning {
        background-color: #fff3cd;
        border: 1px solid #ffeaa7;
        border-radius: 5px;
        padding: 10px;
        margin: 15px 0;
    }
    
    .info {
        background-color: #d1ecf1;
        border: 1px solid #b8daff;
        border-radius: 5px;
        padding: 10px;
        margin: 15px 0;
    }
    
    .toc {
        background-color: #f8f9fa;
        border: 1px solid #e9ecef;
        border-radius: 5px;
        padding: 20px;
        margin: 20px 0;
    }
    
    .toc h2 {
        margin-top: 0;
        color: #2c3e50;
        border-bottom: 1px solid #bdc3c7;
    }
    
    .toc ul {
        list-style-type: none;
        padding-left: 0;
    }
    
    .toc li {
        margin-bottom: 8px;
        padding-left: 15px;
    }
    
    .title-page {
        text-align: center;
        page-break-after: always;
    }
    
    .title-page h1 {
        font-size: 36px;
        color: #2c3e50;
        margin-top: 100px;
        margin-bottom: 20px;
        border-bottom: none;
        page-break-before: auto;
    }
    
    .title-page h3 {
        font-size: 18px;
        color: #7f8c8d;
        margin-bottom: 40px;
    }
    
    .document-info {
        margin-top: 50px;
        padding: 20px;
        background-color: #ecf0f1;
        border-radius: 5px;
    }
    
    .document-info table {
        margin: 0;
        font-size: 11px;
    }
    
    .document-info th {
        background-color: #bdc3c7;
        width: 30%;
    }
    
    hr {
        border: none;
        height: 2px;
        background-color: #bdc3c7;
        margin: 30px 0;
    }
    
    strong {
        color: #2c3e50;
        font-weight: bold;
    }
    
    em {
        color: #555;
        font-style: italic;
    }
    
    .page-break {
        page-break-before: always;
    }
    """
    
    # Create complete HTML document with title page
    title_page = """
    <div class="title-page">
        <h1>VulnHunter</h1>
        <h3>Professional User Manual</h3>
        <h3>Enterprise-Grade Vulnerability Assessment and Penetration Testing Framework</h3>
        
        <div class="document-info">
            <table>
                <tr><th>Document Version</th><td>2.0</td></tr>
                <tr><th>Publication Date</th><td>July 26, 2025</td></tr>
                <tr><th>Classification</th><td>Internal Use Only</td></tr>
                <tr><th>Target Audience</th><td>Security Professionals, Penetration Testers, IT Security Teams</td></tr>
                <tr><th>Document Type</th><td>User Manual</td></tr>
                <tr><th>Total Pages</th><td>Auto-Generated</td></tr>
            </table>
        </div>
        
        <p style="margin-top: 50px; font-size: 14px; color: #7f8c8d;">
            <strong>Developed for cybersecurity professionals, by cybersecurity professionals.</strong><br>
            This document contains proprietary and confidential information.<br>
            Distribution is restricted to authorized personnel only.
        </p>
    </div>
    """
    
    full_html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>VulnHunter User Manual</title>
        <style>{css_styles}</style>
    </head>
    <body>
        {title_page}
        {html_content}
    </body>
    </html>
    """
    
    # Generate PDF
    try:
        print("Generating professional PDF user manual...")
        
        # Create HTML object and generate PDF
        html_doc = HTML(string=full_html)
        pdf_output = 'VulnHunter_User_Manual.pdf'
        
        html_doc.write_pdf(
            pdf_output,
            stylesheets=[CSS(string=css_styles)],
            optimize_images=True
        )
        
        # Get file size for confirmation
        file_size = os.path.getsize(pdf_output)
        file_size_mb = file_size / (1024 * 1024)
        
        print(f"✅ PDF user manual generated successfully!")
        print(f"📄 File: {pdf_output}")
        print(f"📊 Size: {file_size_mb:.2f} MB")
        print(f"📅 Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        return True
        
    except Exception as e:
        print(f"❌ Error generating PDF: {str(e)}")
        return False

if __name__ == "__main__":
    print("VulnHunter User Manual PDF Generator")
    print("=" * 50)
    
    success = generate_pdf_manual()
    
    if success:
        print("\n🎉 Professional user manual PDF generated successfully!")
        print("📋 The manual includes:")
        print("   • Professional title page with document information")
        print("   • Complete table of contents")
        print("   • 13 comprehensive sections covering all aspects")
        print("   • Professional formatting with headers and footers")
        print("   • Code syntax highlighting and table formatting")
        print("   • Legal disclaimers and compliance information")
        print("\n📁 Output file: VulnHunter_User_Manual.pdf")
    else:
        print("\n❌ Failed to generate PDF. Please check the error messages above.")