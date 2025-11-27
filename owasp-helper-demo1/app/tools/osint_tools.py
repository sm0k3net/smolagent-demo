"""OSINT tools for passive reconnaissance using free online services."""
from __future__ import annotations
import os
import json
from typing import Any
import httpx
from smolagents import tool
from app.config import get_settings


def _get_api_key(env_var: str) -> str | None:
    """Get API key from settings or environment."""
    settings = get_settings()
    return getattr(settings, env_var.lower(), None) or os.getenv(env_var)


@tool
def virustotal_domain_report(domain: str) -> str:
    """Query VirusTotal for domain reputation and associated data.

    Args:
        domain: The domain name to look up (e.g., 'example.com').
    Returns: Summary of VirusTotal findings including reputation, categories, and detected URLs.
    """
    api_key = _get_api_key("VIRUSTOTAL_API_KEY")
    if not api_key:
        return "VirusTotal API key not configured. Set VIRUSTOTAL_API_KEY in .env"
    
    try:
        headers = {"x-apikey": api_key}
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        with httpx.Client(timeout=30.0) as client:
            r = client.get(url, headers=headers)
            if r.status_code == 404:
                return f"Domain {domain} not found in VirusTotal"
            r.raise_for_status()
            data = r.json().get("data", {}).get("attributes", {})
            
            result = []
            result.append(f"Domain: {domain}")
            result.append(f"Reputation: {data.get('reputation', 'N/A')}")
            
            stats = data.get("last_analysis_stats", {})
            result.append(f"Analysis: {stats.get('malicious', 0)} malicious, {stats.get('suspicious', 0)} suspicious, {stats.get('harmless', 0)} harmless")
            
            categories = data.get("categories", {})
            if categories:
                result.append(f"Categories: {', '.join(set(categories.values()))}")
            
            return "\n".join(result)
    except Exception as e:
        return f"VirusTotal error: {e}"


@tool
def virustotal_ip_report(ip_address: str) -> str:
    """Query VirusTotal for IP address reputation and associated data.

    Args:
        ip_address: The IP address to look up.
    Returns: Summary of VirusTotal findings for the IP.
    """
    api_key = _get_api_key("VIRUSTOTAL_API_KEY")
    if not api_key:
        return "VirusTotal API key not configured. Set VIRUSTOTAL_API_KEY in .env"
    
    try:
        headers = {"x-apikey": api_key}
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
        with httpx.Client(timeout=30.0) as client:
            r = client.get(url, headers=headers)
            r.raise_for_status()
            data = r.json().get("data", {}).get("attributes", {})
            
            result = []
            result.append(f"IP: {ip_address}")
            result.append(f"Reputation: {data.get('reputation', 'N/A')}")
            result.append(f"Country: {data.get('country', 'N/A')}")
            result.append(f"AS Owner: {data.get('as_owner', 'N/A')}")
            
            stats = data.get("last_analysis_stats", {})
            result.append(f"Analysis: {stats.get('malicious', 0)} malicious, {stats.get('suspicious', 0)} suspicious")
            
            return "\n".join(result)
    except Exception as e:
        return f"VirusTotal error: {e}"


@tool
def shodan_host_info(ip_address: str) -> str:
    """Query Shodan for host information including open ports and services.

    Args:
        ip_address: The IP address to look up.
    Returns: Summary of Shodan findings including ports, services, and vulnerabilities.
    """
    api_key = _get_api_key("SHODAN_API_KEY")
    if not api_key:
        return "Shodan API key not configured. Set SHODAN_API_KEY in .env"
    
    try:
        url = f"https://api.shodan.io/shodan/host/{ip_address}?key={api_key}"
        with httpx.Client(timeout=30.0) as client:
            r = client.get(url)
            if r.status_code == 404:
                return f"No Shodan data found for {ip_address}"
            r.raise_for_status()
            data = r.json()
            
            result = []
            result.append(f"IP: {ip_address}")
            result.append(f"Organization: {data.get('org', 'N/A')}")
            result.append(f"ISP: {data.get('isp', 'N/A')}")
            result.append(f"Country: {data.get('country_name', 'N/A')}")
            result.append(f"OS: {data.get('os', 'N/A')}")
            
            ports = data.get("ports", [])
            result.append(f"Open Ports: {', '.join(map(str, ports[:20]))}")
            
            vulns = data.get("vulns", [])
            if vulns:
                result.append(f"Vulnerabilities: {', '.join(vulns[:10])}")
            
            # Service details
            for svc in data.get("data", [])[:5]:
                port = svc.get("port")
                product = svc.get("product", "unknown")
                version = svc.get("version", "")
                result.append(f"  - Port {port}: {product} {version}".strip())
            
            return "\n".join(result)
    except Exception as e:
        return f"Shodan error: {e}"


@tool
def shodan_search(query: str, max_results: int = 10) -> str:
    """Search Shodan for hosts matching a query.

    Args:
        query: Shodan search query (e.g., 'apache country:US', 'port:22 org:Amazon').
        max_results: Maximum number of results to return (default 10).
    Returns: List of matching hosts with basic info.
    """
    api_key = _get_api_key("SHODAN_API_KEY")
    if not api_key:
        return "Shodan API key not configured. Set SHODAN_API_KEY in .env"
    
    try:
        url = f"https://api.shodan.io/shodan/host/search?key={api_key}&query={query}"
        with httpx.Client(timeout=30.0) as client:
            r = client.get(url)
            r.raise_for_status()
            data = r.json()
            
            result = [f"Shodan Search: {query}", f"Total: {data.get('total', 0)} results", ""]
            
            for match in data.get("matches", [])[:max_results]:
                ip = match.get("ip_str")
                port = match.get("port")
                org = match.get("org", "N/A")
                product = match.get("product", "unknown")
                result.append(f"- {ip}:{port} | {org} | {product}")
            
            return "\n".join(result)
    except Exception as e:
        return f"Shodan error: {e}"


@tool
def hunter_domain_search(domain: str) -> str:
    """Search Hunter.io for email addresses associated with a domain.

    Args:
        domain: The domain to search for emails (e.g., 'example.com').
    Returns: List of discovered email addresses and patterns.
    """
    api_key = _get_api_key("HUNTER_API_KEY")
    if not api_key:
        return "Hunter.io API key not configured. Set HUNTER_API_KEY in .env"
    
    try:
        url = f"https://api.hunter.io/v2/domain-search?domain={domain}&api_key={api_key}"
        with httpx.Client(timeout=30.0) as client:
            r = client.get(url)
            r.raise_for_status()
            data = r.json().get("data", {})
            
            result = []
            result.append(f"Domain: {domain}")
            result.append(f"Organization: {data.get('organization', 'N/A')}")
            result.append(f"Email Pattern: {data.get('pattern', 'N/A')}")
            result.append(f"Emails Found: {len(data.get('emails', []))}")
            result.append("")
            
            for email in data.get("emails", [])[:15]:
                addr = email.get("value")
                first = email.get("first_name", "")
                last = email.get("last_name", "")
                position = email.get("position", "")
                confidence = email.get("confidence", 0)
                name_part = f"{first} {last}".strip() or "Unknown"
                result.append(f"- {addr} | {name_part} | {position} | {confidence}% confidence")
            
            return "\n".join(result)
    except Exception as e:
        return f"Hunter.io error: {e}"


@tool
def dns_lookup(domain: str, record_type: str = "A") -> str:
    """Perform DNS lookup using public DNS-over-HTTPS.

    Args:
        domain: The domain name to look up.
        record_type: DNS record type (A, AAAA, MX, NS, TXT, CNAME, SOA).
    Returns: DNS records found.
    """
    try:
        url = f"https://dns.google/resolve?name={domain}&type={record_type}"
        with httpx.Client(timeout=15.0) as client:
            r = client.get(url)
            r.raise_for_status()
            data = r.json()
            
            if data.get("Status") != 0:
                return f"DNS lookup failed for {domain} (status: {data.get('Status')})"
            
            result = [f"DNS {record_type} records for {domain}:"]
            for answer in data.get("Answer", []):
                rtype = answer.get("type")
                rdata = answer.get("data")
                ttl = answer.get("TTL")
                result.append(f"  - {rdata} (TTL: {ttl})")
            
            if not data.get("Answer"):
                result.append("  No records found")
            
            return "\n".join(result)
    except Exception as e:
        return f"DNS lookup error: {e}"


@tool
def whois_lookup(domain: str) -> str:
    """Perform WHOIS lookup for domain registration info using web API.

    Args:
        domain: The domain name to look up.
    Returns: WHOIS registration information.
    """
    try:
        # Use a free WHOIS API
        url = f"https://www.whoisxmlapi.com/whoisserver/WhoisService?domainName={domain}&outputFormat=json"
        api_key = _get_api_key("WHOISXML_API_KEY")
        if api_key:
            url += f"&apiKey={api_key}"
        
        with httpx.Client(timeout=30.0) as client:
            r = client.get(url)
            r.raise_for_status()
            data = r.json().get("WhoisRecord", {})
            
            result = [f"WHOIS for {domain}:"]
            result.append(f"  Registrar: {data.get('registrarName', 'N/A')}")
            result.append(f"  Created: {data.get('createdDate', 'N/A')}")
            result.append(f"  Updated: {data.get('updatedDate', 'N/A')}")
            result.append(f"  Expires: {data.get('expiresDate', 'N/A')}")
            
            registrant = data.get("registrant", {})
            if registrant:
                result.append(f"  Organization: {registrant.get('organization', 'N/A')}")
                result.append(f"  Country: {registrant.get('country', 'N/A')}")
            
            nameservers = data.get("nameServers", {}).get("hostNames", [])
            if nameservers:
                result.append(f"  Nameservers: {', '.join(nameservers[:4])}")
            
            return "\n".join(result)
    except Exception as e:
        return f"WHOIS lookup error: {e}"


@tool
def crt_sh_search(domain: str) -> str:
    """Search crt.sh for SSL/TLS certificates to discover subdomains.

    Args:
        domain: The domain to search for certificates.
    Returns: List of discovered subdomains from certificate transparency logs.
    """
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        with httpx.Client(timeout=60.0) as client:
            r = client.get(url)
            r.raise_for_status()
            data = r.json()
            
            # Extract unique subdomains
            subdomains = set()
            for cert in data:
                name = cert.get("name_value", "")
                for line in name.split("\n"):
                    line = line.strip().lower()
                    if line.endswith(domain.lower()):
                        subdomains.add(line)
            
            result = [f"Certificate Transparency subdomains for {domain}:", f"Found {len(subdomains)} unique names:", ""]
            for sub in sorted(subdomains)[:50]:
                result.append(f"  - {sub}")
            
            if len(subdomains) > 50:
                result.append(f"  ... and {len(subdomains) - 50} more")
            
            return "\n".join(result)
    except Exception as e:
        return f"crt.sh error: {e}"


@tool  
def securitytrails_domain_info(domain: str) -> str:
    """Query SecurityTrails for domain information including subdomains and DNS history.

    Args:
        domain: The domain to look up.
    Returns: Domain information from SecurityTrails.
    """
    api_key = _get_api_key("SECURITYTRAILS_API_KEY")
    if not api_key:
        return "SecurityTrails API key not configured. Set SECURITYTRAILS_API_KEY in .env"
    
    try:
        headers = {"APIKEY": api_key}
        
        # Get domain info
        url = f"https://api.securitytrails.com/v1/domain/{domain}"
        with httpx.Client(timeout=30.0) as client:
            r = client.get(url, headers=headers)
            r.raise_for_status()
            data = r.json()
            
            result = [f"SecurityTrails info for {domain}:"]
            result.append(f"  Alexa Rank: {data.get('alexa_rank', 'N/A')}")
            
            current = data.get("current_dns", {})
            
            # A records
            a_records = current.get("a", {}).get("values", [])
            if a_records:
                ips = [r.get("ip") for r in a_records[:5]]
                result.append(f"  A Records: {', '.join(ips)}")
            
            # MX records
            mx_records = current.get("mx", {}).get("values", [])
            if mx_records:
                mxs = [r.get("hostname") for r in mx_records[:3]]
                result.append(f"  MX Records: {', '.join(mxs)}")
            
            # NS records
            ns_records = current.get("ns", {}).get("values", [])
            if ns_records:
                nss = [r.get("nameserver") for r in ns_records[:4]]
                result.append(f"  NS Records: {', '.join(nss)}")
            
            return "\n".join(result)
    except Exception as e:
        return f"SecurityTrails error: {e}"


@tool
def haveibeenpwned_domain(domain: str) -> str:
    """Check Have I Been Pwned for breaches associated with a domain.

    Args:
        domain: The domain to check for breaches.
    Returns: List of breaches affecting the domain.
    
    Note: Requires Have I Been Pwned API key for domain search.
    """
    api_key = _get_api_key("HIBP_API_KEY")
    if not api_key:
        return "HIBP API key not configured. Set HIBP_API_KEY in .env (requires paid subscription)"
    
    try:
        headers = {
            "hibp-api-key": api_key,
            "user-agent": "OWASP-SmolAgent"
        }
        url = f"https://haveibeenpwned.com/api/v3/breaches?domain={domain}"
        with httpx.Client(timeout=30.0) as client:
            r = client.get(url, headers=headers)
            if r.status_code == 404:
                return f"No breaches found for domain {domain}"
            r.raise_for_status()
            breaches = r.json()
            
            result = [f"Breaches for {domain}:", f"Found {len(breaches)} breaches:", ""]
            
            for breach in breaches[:10]:
                name = breach.get("Name")
                date = breach.get("BreachDate")
                count = breach.get("PwnCount", 0)
                data_classes = ", ".join(breach.get("DataClasses", [])[:5])
                result.append(f"  - {name} ({date}): {count:,} accounts")
                result.append(f"    Data: {data_classes}")
            
            return "\n".join(result)
    except Exception as e:
        return f"HIBP error: {e}"
