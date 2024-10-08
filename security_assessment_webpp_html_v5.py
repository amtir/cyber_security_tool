import os
import subprocess
from datetime import datetime
import html  # for escaping HTML special characters
import re  # For extracting IPs

# Function to print verbose log messages with timestamps
def log(message, success=True):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    status = "[+]" if success else "[-]"
    print(f"{timestamp} {status} {message}")

# Function to execute shell commands
def run_command(command, description):
    try:
        log(f"Starting {description}")
        start_time = datetime.now()
        result = subprocess.run(command, shell=True, text=True, capture_output=True)
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        if result.returncode == 0:
            log(f"{description} completed successfully in {duration} seconds", success=True)
        else:
            log(f"{description} failed in {duration} seconds", success=False)
        
        return result.stdout
    except Exception as e:
        log(f"Error during {description}: {e}", success=False)
        return str(e)

# Create a folder for storing outputs
def create_output_folder(domain_or_ip):
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    folder_name = f"{domain_or_ip}_{timestamp}"
    os.makedirs(folder_name, exist_ok=True)
    return folder_name

# Function to perform WHOIS lookup
def whois_lookup(domain_or_ip):
    return run_command(f"whois {domain_or_ip}", f"WHOIS lookup for {domain_or_ip}")

# Function to perform DNS lookup using Google DNS (8.8.8.8)
def dns_lookup(domain):
    return run_command(f"dig all @8.8.8.8 {domain} ANY", f"DNS lookup for {domain} using Google DNS")

# Function to extract IPs from WHOIS and DNS lookup results, filtering out 8.8.8.8 and private IP ranges
def extract_ips(data):
    ips = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', data)
    filtered_ips = [ip for ip in ips if ip != '8.8.8.8' and not ip.startswith('192.168.')]
    return filtered_ips

# Function to run nmap scan on an IP
def nmap_scan(ip):
    log(f"Starting Nmap scan for {ip}")
    return run_command(f"nmap -sS -A {ip}", f"Nmap scan for {ip}")

# Function to sanitize output for HTML display
def sanitize_output(data):
    return html.escape(data)

# Function to run vulnerability scan using Nmap's vulners script on an IP
def vulners_scan(ip):
    log(f"Starting Nmap vulnerability scan for {ip}")
    return run_command(f"nmap -sV --script vulners {ip}", f"Vulnerability scan for {ip}")


# Function to generate HTML report with collapsible sections and stages
def generate_html_report(domain_or_ip, results_dict, stage_2_results, stage_3_results, gathered_ips, output_folder):
    now = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = os.path.join(output_folder, f"Security_Assessment_{domain_or_ip}_{now}.html")

    log(f"Generating HTML report: {filename}")

    html_template = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Security Assessment Report for {domain_or_ip}</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js"></script>
    </head>
    <body>
        <div class="container mt-4">
            <h1>Security Assessment Report for {domain_or_ip}</h1>

            <h2>Stage 1: Information Gathering & Reconnaissance</h2>
            <div class="accordion" id="accordionExample">
    """

    # Stage 1: Information Gathering Results (WHOIS, DNS, Subdomains)
    for idx, (key, data) in enumerate(results_dict.items()):
        sanitized_data = sanitize_output(data)
        collapse_id = f"collapse-{idx}"
        header_id = f"heading-{idx}"

        html_template += f"""
        <div class="accordion-item">
            <h2 class="accordion-header" id="{header_id}">
                <button class="accordion-button {'collapsed' if idx != 0 else ''}" type="button" data-bs-toggle="collapse" data-bs-target="#{collapse_id}" aria-expanded="{'true' if idx == 0 else 'false'}" aria-controls="{collapse_id}">
                    {key}
                </button>
            </h2>
            <div id="{collapse_id}" class="accordion-collapse collapse {'show' if idx == 0 else ''}" aria-labelledby="{header_id}" data-bs-parent="#accordionExample">
                <div class="accordion-body">
                    <pre>{sanitized_data}</pre>
                </div>
            </div>
        </div>
        """

    # Stage 2: Scanning and Enumeration Results (Nmap)
    html_template += f"""
            </div>
            <h2 class="mt-4">Stage 2: Scanning and Enumeration</h2>
            <p><strong>Total IPs Found:</strong> {len(gathered_ips)}</p>
            <p><strong>All IPs:</strong> {', '.join(gathered_ips)}</p>
            <div class="accordion" id="accordionStage2">
    """

    for idx, (ip, nmap_result) in enumerate(stage_2_results.items()):
        sanitized_nmap = sanitize_output(nmap_result)
        collapse_id = f"nmap-collapse-{idx}"
        header_id = f"nmap-heading-{idx}"

        html_template += f"""
        <div class="accordion-item">
            <h2 class="accordion-header" id="{header_id}">
                <button class="accordion-button {'collapsed' if idx != 0 else ''}" type="button" data-bs-toggle="collapse" data-bs-target="#{collapse_id}" aria-expanded="{'true' if idx == 0 else 'false'}" aria-controls="{collapse_id}">
                    Nmap Scan Results for IP: {ip}
                </button>
            </h2>
            <div id="{collapse_id}" class="accordion-collapse collapse {'show' if idx == 0 else ''}" aria-labelledby="{header_id}" data-bs-parent="#accordionStage2">
                <div class="accordion-body">
                    <pre>{sanitized_nmap}</pre>
                </div>
            </div>
        </div>
        """

    # Stage 3: Vulnerability Scanning (vulners)
    html_template += f"""
            </div>
            <h2 class="mt-4">Stage 3: Vulnerability Scanning</h2>
            <div class="accordion" id="accordionStage3">
    """

    for idx, (ip, vulners_result) in enumerate(stage_3_results.items()):
        sanitized_vulners = sanitize_output(vulners_result)
        collapse_id = f"vulners-collapse-{idx}"
        header_id = f"vulners-heading-{idx}"

        html_template += f"""
        <div class="accordion-item">
            <h2 class="accordion-header" id="{header_id}">
                <button class="accordion-button {'collapsed' if idx != 0 else ''}" type="button" data-bs-toggle="collapse" data-bs-target="#{collapse_id}" aria-expanded="{'true' if idx == 0 else 'false'}" aria-controls="{collapse_id}">
                    Vulnerability Scan Results for IP: {ip}
                </button>
            </h2>
            <div id="{collapse_id}" class="accordion-collapse collapse {'show' if idx == 0 else ''}" aria-labelledby="{header_id}" data-bs-parent="#accordionStage3">
                <div class="accordion-body">
                    <pre>{sanitized_vulners}</pre>
                </div>
            </div>
        </div>
        """

    # Close HTML
    html_template += """
            </div>
        </div>
    </body>
    </html>
    """

    # Write the HTML file
    with open(filename, "w") as file:
        file.write(html_template)
    
    log(f"HTML report successfully generated: {filename}")


def subdomain_discovery(domain, output_folder):
    now = datetime.now().strftime("%Y%m%d%H%M%S")
    output_file = os.path.join(output_folder, f"{domain}_subdomains_{now}.txt")
    log(f"Starting subdomain discovery for {domain} with Sublist3r")
    sublist3r_command = f"sublist3r -d {domain} -o {output_file}"
    result = run_command(sublist3r_command, f"Subdomain discovery for {domain}")
    
    # Check if the file was actually created
    if os.path.exists(output_file):
        log(f"Subdomain discovery completed and output file created: {output_file}")
    else:
        log(f"Subdomain discovery completed but no output file found for {domain}.", success=False)
    
    return result, output_file

def main():
    print("Security Assessment Tool")
    print("=======================")
    print("1. Enter a domain name")
    print("2. Enter an IP address")
    print("3. Quit")
    
    choice = input("Choose an option (1/2/3): ")
    
    if choice == '1':
        domain = input("Enter domain name: ")
        output_folder = create_output_folder(domain)  # Create output folder based on domain
        results = {}
        gathered_ips = set()

        # Step 1: Domain-based actions (Information Gathering & Reconnaissance)
        whois_data = whois_lookup(domain)
        dns_data = dns_lookup(domain)
        
        # Subdomain discovery using Sublist3r with timestamped output file
        sublist3r_result, subdomain_output_file = subdomain_discovery(domain, output_folder)

        # Read subdomains from the output file if it exists
        if os.path.exists(subdomain_output_file):
            with open(subdomain_output_file, 'r') as file:
                subdomains = file.read()
        else:
            subdomains = "No subdomains found or error during discovery."
        
        # Save results
        results['WHOIS'] = whois_data
        results['DNS Lookup'] = dns_data
        results['Subdomains'] = subdomains

        gathered_ips.update(extract_ips(whois_data))
        gathered_ips.update(extract_ips(dns_data))
        #gathered_ips.update(extract_ips(subdomains))

        # Step 2: Scanning and Enumeration
        stage_2_results = {ip: nmap_scan(ip) for ip in gathered_ips}

        # Step 3: Vulnerability Scanning
        stage_3_results = {ip: vulners_scan(ip) for ip in gathered_ips}

        # Generate HTML report inside the output folder
        generate_html_report(domain, results, stage_2_results, stage_3_results, gathered_ips, output_folder)

    elif choice == '2':
        ip = input("Enter IP address: ")
        output_folder = create_output_folder(ip)  # Create output folder based on IP address
        results = {}
        
        # Step 1: IP-based actions
        reverse_dns_data = run_command(f"dig -x {ip}", f"Reverse DNS lookup for {ip}")
        whois_data = whois_lookup(ip)
        
        # Save results
        results['Reverse DNS Lookup'] = reverse_dns_data
        results['WHOIS'] = whois_data
        
        # Step 2: Scan the IP
        stage_2_results = {ip: nmap_scan(ip)}

        # Step 3: Vulnerability Scanning
        stage_3_results = {ip: vulners_scan(ip)}

        # Generate HTML report inside the output folder
        generate_html_report(ip, results, stage_2_results, stage_3_results, [ip], output_folder)
    
    else:
        log("Exiting...", success=True)

if __name__ == "__main__":
    main()
