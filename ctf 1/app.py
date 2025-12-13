from flask import Flask, render_template, request, abort
import socket
import ssl
import subprocess
import ipaddress
import re
import os

with open("/app/flag.txt","r") as f:
    flag_content=f.read()

os.unlink("/app/flag.txt")


class Validator:
    def __init__(self):
        self.name = "Validator"
    
    def parse(self, url):
        if not url or not isinstance(url, str):
            return None
        url = url.strip()
        if not (url.startswith('http://') or url.startswith('https://')):
            if '://' in url:
                return None
            else:
                url = 'http://' + url
        if url.startswith('https://'):
            scheme = 'https'
            rest = url[8:]
        else:
            scheme = 'http'
            rest = url[7:]
        if '/' in rest:
            host_part, path = rest.split('/', 1)
            path = '/' + path
        else:
            host_part = rest
            path = '/'
        if '@' in host_part:
            host_port, ignored_part = host_part.split('@', 1)
        else:
            host_port = host_part
        if ':' in host_port and not self._looks_like_ipv6(host_port):
            host, port_str = host_port.rsplit(':', 1)
            try:
                port = int(port_str)
            except ValueError:
                port = 443 if scheme == 'https' else 80
        else:
            host = host_port
            port = 443 if scheme == 'https' else 80
        host = host.lower().strip()
        parsed = {
            'scheme': scheme,
            'hostname': host,
            'port': port,
            'path': path,
            'original_url': url,
            'parser': 'Validator'
        }
        return parsed
    
    def _looks_like_ipv6(self, host_port):
        return host_port.count(':') > 1
    
    def is_valid_target(self, hostname):
        ips = self._resolve_hostname(hostname)
        if not ips:
            return False
        for ip_str in ips:
            try:
                ip = ipaddress.ip_address(ip_str)
                if (ip.is_loopback or ip.is_private or ip.is_link_local or 
                    ip.is_reserved or ip.is_multicast or ip.is_unspecified):
                    return False
            except ValueError:
                return False
        return True
    
    def _resolve_hostname(self, host):
        try:
            result = subprocess.run(
                ["dig", "+short", host, "A"],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=5
            )
            ips = [line.strip() for line in result.stdout.splitlines() if line.strip()]
            return ips
        except subprocess.TimeoutExpired:
            return []
        except Exception:
            return []


class Requester:
    def __init__(self):
        self.name = "Requester"
    
    def parse(self, url):
        if not url or not isinstance(url, str):
            return None
        url = url.strip()
        if '://' not in url:
            url = 'http://' + url
        scheme_part, rest = url.split('://', 1)
        scheme = scheme_part.lower()
        if '@' in rest:
            parts = rest.split('@')
            rest = parts[-1]
        if rest.startswith('['):
            bracket_end = rest.find(']')
            if bracket_end != -1:
                host = rest[1:bracket_end]
                rest_after_host = rest[bracket_end + 1:]
                if rest_after_host.startswith(':'):
                    port_and_path = rest_after_host[1:]
                    if '/' in port_and_path:
                        port_str, path_part = port_and_path.split('/', 1)
                        path = '/' + path_part
                    else:
                        port_str = port_and_path
                        path = '/'
                    try:
                        port = int(port_str)
                    except ValueError:
                        port = 443 if scheme == 'https' else 80
                else:
                    path = rest_after_host if rest_after_host.startswith('/') else ('/' + rest_after_host if rest_after_host else '/')
                    port = 443 if scheme == 'https' else 80
            else:
                host = rest.split('/')[0].split(':')[0]
                path = '/' + '/'.join(rest.split('/')[1:]) if '/' in rest else '/'
                port = 443 if scheme == 'https' else 80
        else:
            if '/' in rest:
                host_port, path_part = rest.split('/', 1)
                path = '/' + path_part
            else:
                host_port = rest
                path = '/'
            if ':' in host_port and not self._is_ipv6(host_port):
                host, port_str = host_port.rsplit(':', 1)
                try:
                    port = int(port_str)
                except ValueError:
                    port = 443 if scheme == 'https' else 80
            else:
                host = host_port
                port = 443 if scheme == 'https' else 80
        host = host.lower()
        replacements = {
            '%6c': 'l', '%4c': 'l',
            '%6f': 'o', '%4f': 'o',
            '%63': 'c', '%43': 'c',
            '%61': 'a', '%41': 'a',
            '%6c%6f%63%61%6c%68%6f%73%74': 'localhost',
            '%2e': '.',
            '%30': '0', '%31': '1', '%32': '2', '%33': '3',
            '%34': '4', '%35': '5', '%36': '6', '%37': '7',
            '%38': '8', '%39': '9'
        }
        for encoded, decoded in replacements.items():
            host = host.replace(encoded, decoded)
        return {
            'scheme': scheme,
            'hostname': host,
            'port': port,
            'path': path,
            'original_url': url,
            'parser': 'Requester'
        }
    
    def _is_ipv6(self, host_port):
        return host_port.count(':') > 1
    
    def make_request(self, parsed_url, timeout=5):
        try:
            host = parsed_url['hostname']
            port = parsed_url['port']
            path = parsed_url['path']
            scheme = parsed_url['scheme']
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            try:
                sock.connect((host, port))
                if scheme == 'https':
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    sock = context.wrap_socket(sock, server_hostname=host)
                http_request = f"GET {path} HTTP/1.1\r\n"
                http_request += f"Host: {host}\r\n"
                http_request += "User-Agent: URLParsingConfusion/1.0\r\n"
                http_request += "Connection: close\r\n"
                http_request += "\r\n"
                sock.sendall(http_request.encode('utf-8'))
                response_data = b""
                while True:
                    try:
                        chunk = sock.recv(4096)
                        if not chunk:
                            break
                        response_data += chunk
                        if len(response_data) > 100000:
                            break
                    except socket.timeout:
                        break
                response_str = response_data.decode('utf-8', errors='ignore')
                if '\r\n\r\n' in response_str:
                    headers, body = response_str.split('\r\n\r\n', 1)
                else:
                    headers, body = response_str, ""
                status_line = headers.split('\r\n')[0]
                status_match = re.search(r'HTTP/\d\.\d\s+(\d+)', status_line)
                status_code = int(status_match.group(1)) if status_match else 200
                if 300 <= status_code < 400:
                    for line in headers.split('\r\n')[1:]:
                        if line.lower().startswith('location:'):
                            redirect_url = line.split(':', 1)[1].strip()
                            return f"Redirect to: {redirect_url}\n\nOriginal response:\n{body[:500]}"
                return body[:1000]
            finally:
                sock.close()
        except Exception as e:
            return f"Error making socket request: {str(e)}"


validator = Validator()
requester = Requester()

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    content = ""
    url = ""
    error_message = ""
    debug_info = {}
    if request.method == "POST":
        url = request.form.get("url", "").strip()
        if not url:
            error_message = "Please provide a URL."
        else:
            try:
                validator_parsed = validator.parse(url)
                requester_parsed = requester.parse(url)
                debug_info = {
                    'original_url': url,
                    'validator_result': validator_parsed,
                    'requester_result': requester_parsed
                }
                print(f"Debug - Validator Result: {validator_parsed}")
                print(f"Debug - Requester Result: {requester_parsed}")
                if not validator_parsed:
                    error_message = "Invalid URL format - Validator rejected the URL completely."
                elif validator_parsed['scheme'] not in ["http", "https"]:
                    error_message = f"Only HTTP and HTTPS schemes are allowed. Validator saw scheme: '{validator_parsed['scheme']}'"
                elif not validator_parsed['hostname']:
                    error_message = "Invalid hostname - Validator could not extract a valid hostname from URL."
                elif not validator.is_valid_target(validator_parsed['hostname']):
                    error_message = f"Access denied - Validator detected '{validator_parsed['hostname']}' resolves to internal/private addresses."
                else:
                    if requester_parsed:
                        content = requester.make_request(requester_parsed)
                    else:
                        error_message = "Requester failed to parse URL - Both parsers failed."
            except Exception as e:
                error_message = f"Error processing URL: {str(e)}"
    return render_template("index.html", 
                         content=content, 
                         url=url, 
                         error_message=error_message,
                         debug_info=debug_info)

@app.route("/flag")
def flag():
    if request.remote_addr != "127.0.0.1":
        abort(403, "Forbidden - Only accessible from localhost")
    return f"Your secret flag:  {flag_content}"

@app.route("/health")
def health():
    return {"status": "ok", "message": "URL Parsing Confusion App is running"}

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
