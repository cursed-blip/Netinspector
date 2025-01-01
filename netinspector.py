import tkinter as tk
from tkinter import ttk, messagebox
import requests
import socket
import subprocess
import whois
import ssl
import smtplib
from urllib.parse import urlparse

def get_ip_geolocation(ip):
    response = requests.get(f"https://ipinfo.io/{ip}/json")
    return response.json()

def get_traceroute(ip):
    try:
        result = subprocess.check_output(['traceroute', ip], stderr=subprocess.STDOUT)
        return result.decode('utf-8')
    except subprocess.CalledProcessError as e:
        return e.output.decode('utf-8')

def get_whois_info(domain):
    try:
        w = whois.whois(domain)
        return str(w)
    except Exception as e:
        return str(e)

def get_http_headers(url):
    try:
        response = requests.head(url)
        return response.headers
    except Exception as e:
        return str(e)

def check_ssl_certificate(domain):
    try:
        ssl_info = ssl.get_server_certificate((domain, 443))
        return ssl_info
    except Exception as e:
        return str(e)

def reverse_dns_lookup(ip):
    try:
        result = socket.gethostbyaddr(ip)
        return result
    except socket.herror:
        return "No PTR record found"

def find_subdomains(domain):
    return ["sub1." + domain, "sub2." + domain]

def ping_utility(ip):
    try:
        result = subprocess.check_output(['ping', '-c', '4', ip])
        return result.decode('utf-8')
    except subprocess.CalledProcessError as e:
        return str(e)

def check_smtp_email(email):
    try:
        domain = email.split('@')[1]
        result = subprocess.check_output(['nslookup', '-type=mx', domain])
        return result.decode('utf-8')
    except Exception as e:
        return str(e)

def check_port_forwarding(ip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        result = s.connect_ex((ip, port))
        s.close()
        if result == 0:
            return f"Port {port} is open"
        else:
            return f"Port {port} is closed"
    except Exception as e:
        return str(e)

def dns_cache_viewer():
    try:
        cache = subprocess.check_output(['ipconfig', '/displaydns'])
        return cache.decode('utf-8')
    except subprocess.CalledProcessError as e:
        return str(e)

def monitor_uptime(url):
    try:
        response = requests.get(url)
        if response.status_code == 200:
            return "Site is up"
        else:
            return "Site is down"
    except requests.RequestException:
        return "Site is down"

def on_submit():
    ip_or_domain = entry.get()
    selected_tool = combo.get()
    
    if selected_tool == "IP Geolocation":
        result.set(get_ip_geolocation(ip_or_domain))
    elif selected_tool == "Traceroute":
        result.set(get_traceroute(ip_or_domain))
    elif selected_tool == "Whois Lookup":
        result.set(get_whois_info(ip_or_domain))
    elif selected_tool == "HTTP Header Viewer":
        result.set(get_http_headers(ip_or_domain))
    elif selected_tool == "SSL Certificate Checker":
        result.set(check_ssl_certificate(ip_or_domain))
    elif selected_tool == "Reverse DNS Lookup":
        result.set(reverse_dns_lookup(ip_or_domain))
    elif selected_tool == "Subdomain Finder":
        result.set(find_subdomains(ip_or_domain))
    elif selected_tool == "Ping Utility":
        result.set(ping_utility(ip_or_domain))
    elif selected_tool == "SMTP Email Tester":
        result.set(check_smtp_email(ip_or_domain))
    elif selected_tool == "Port Forwarding Tester":
        port = entry2.get()
        result.set(check_port_forwarding(ip_or_domain, port))
    elif selected_tool == "DNS Cache Viewer":
        result.set(dns_cache_viewer())
    elif selected_tool == "Network Uptime Monitor":
        result.set(monitor_uptime(ip_or_domain))

root = tk.Tk()
root.title("NetInspector")
root.geometry("600x400")

tk.Label(root, text="Enter IP/Domain:").pack(pady=5)
entry = tk.Entry(root, width=40)
entry.pack(pady=5)

tk.Label(root, text="Enter Port (if needed):").pack(pady=5)
entry2 = tk.Entry(root, width=40)
entry2.pack(pady=5)

tk.Label(root, text="Select a Tool:").pack(pady=5)
tools = [
    "IP Geolocation", "Traceroute", "Whois Lookup", "HTTP Header Viewer",
    "SSL Certificate Checker", "Reverse DNS Lookup", "Subdomain Finder",
    "Ping Utility", "SMTP Email Tester", "Port Forwarding Tester", 
    "DNS Cache Viewer", "Network Uptime Monitor"
]
combo = ttk.Combobox(root, values=tools, state="readonly", width=30)
combo.pack(pady=5)

submit_btn = tk.Button(root, text="Submit", command=on_submit)
submit_btn.pack(pady=20)

result = tk.StringVar()
result_label = tk.Label(root, textvariable=result, wraplength=500)
result_label.pack(pady=5)

root.mainloop()
