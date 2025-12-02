"""
Enhanced VirusTotal Tools for OWASP Security Agent
==================================================
Comprehensive VirusTotal API integration for:
- Subdomain discovery
- Domain reputation analysis
- IP intelligence
- URL scanning
- File hash analysis
- Historical WHOIS data
- SSL certificate information
- Passive DNS data

API Documentation: https://docs.virustotal.com/reference/overview
"""

import os
import json
import time
from typing import Optional, List, Dict, Any
from smolagents import tool

# Try to import httpx
try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False

# Try to import from app config
try:
    from app.config import get_settings
    HAS_CONFIG = True
except ImportError:
    HAS_CONFIG = False


def _get_api_key() -> Optional[str]:
    """Get VirusTotal API key from settings or environment."""
    if HAS_CONFIG:
        settings = get_settings()
        key = getattr(settings, 'virustotal_api_key', None)
        if key:
            return key
    return os.getenv("VIRUSTOTAL_API_KEY")


def _make_vt_request(
    endpoint: str,
    params: Optional[Dict] = None,
    method: str = "GET"
) -> Dict[str, Any]:
    """Make a request to VirusTotal API v3."""
    api_key = _get_api_key()
    if not api_key:
        return {"error": "VirusTotal API key not configured. Set VIRUSTOTAL_API_KEY environment variable."}
    
    if not HAS_HTTPX:
        return {"error": "httpx library not installed. Run: pip install httpx"}
    
    base_url = "https://www.virustotal.com/api/v3"
    url = f"{base_url}/{endpoint}"
    
    headers = {
        "x-apikey": api_key,
        "Accept": "application/json"
    }
    
    try:
        with httpx.Client(timeout=60.0) as client:
            if method == "GET":
                response = client.get(url, headers=headers, params=params)
            elif method == "POST":
                response = client.post(url, headers=headers, json=params)
            else:
                return {"error": f"Unsupported method: {method}"}
            
            if response.status_code == 401:
                return {"error": "Invalid VirusTotal API key"}
            elif response.status_code == 404:
                return {"error": "Resource not found", "status": 404}
            elif response.status_code == 429:
                return {"error": "Rate limit exceeded. VirusTotal free tier allows 4 requests/minute."}
            elif response.status_code != 200:
                return {"error": f"HTTP {response.status_code}", "details": response.text[:500]}
            
            return response.json()
            
    except httpx.TimeoutException:
        return {"error": "Request timeout"}
    except Exception as e:
        return {"error": f"Request failed: {str(e)}"}


@tool
def virustotal_subdomains(domain: str, max_results: int = 100) -> str:
    """
    Discover subdomains of a domain using VirusTotal's passive DNS data.
    
    VirusTotal aggregates subdomain information from multiple sources including:
    - Passive DNS records
    - SSL certificate transparency logs
    - Web crawlers and scanners
    
    This is excellent for reconnaissance and asset discovery during security assessments.
    
    Args:
        domain: The root domain to find subdomains for (e.g., 'example.com')
        max_results: Maximum number of subdomains to return (default 100, max 500)
    
    Returns:
        JSON string with discovered subdomains and their metadata
    """
    max_results = min(max(1, max_results), 500)
    
    endpoint = f"domains/{domain}/subdomains"
    params = {"limit": min(max_results, 40)}  # VT API limit per request
    
    all_subdomains = []
    cursor = None
    
    while len(all_subdomains) < max_results:
        if cursor:
            params["cursor"] = cursor
        
        result = _make_vt_request(endpoint, params)
        
        if "error" in result:
            if all_subdomains:
                # Return what we have so far
                break
            return json.dumps(result)
        
        data = result.get("data", [])
        if not data:
            break
        
        for item in data:
            subdomain_id = item.get("id", "")
            all_subdomains.append({
                "subdomain": subdomain_id,
                "type": item.get("type", "domain")
            })
        
        # Check for pagination
        cursor = result.get("meta", {}).get("cursor")
        if not cursor or len(all_subdomains) >= max_results:
            break
        
        # Rate limiting - VT free tier allows 4 req/min
        time.sleep(0.5)
    
    return json.dumps({
        "domain": domain,
        "subdomain_count": len(all_subdomains),
        "subdomains": all_subdomains[:max_results],
        "note": "Use these subdomains for further reconnaissance and vulnerability assessment"
    }, indent=2)


@tool
def virustotal_domain_analysis(domain: str) -> str:
    """
    Get comprehensive domain analysis from VirusTotal.
    
    Returns detailed information including:
    - Domain reputation score
    - Detection statistics from 70+ security vendors
    - Categories and tags
    - WHOIS information
    - DNS records
    - Historical data
    
    Args:
        domain: The domain to analyze (e.g., 'example.com')
    
    Returns:
        JSON string with comprehensive domain analysis
    """
    endpoint = f"domains/{domain}"
    result = _make_vt_request(endpoint)
    
    if "error" in result:
        return json.dumps(result)
    
    data = result.get("data", {})
    attrs = data.get("attributes", {})
    
    # Extract key information
    analysis_stats = attrs.get("last_analysis_stats", {})
    categories = attrs.get("categories", {})
    
    # Get DNS records
    dns_records = []
    for record_type in ["last_dns_records", "dns_records"]:
        records = attrs.get(record_type, [])
        for r in records[:20]:
            dns_records.append({
                "type": r.get("type", ""),
                "value": r.get("value", ""),
                "ttl": r.get("ttl", "")
            })
    
    # WHOIS data
    whois = attrs.get("whois", "")
    whois_date = attrs.get("whois_date", "")
    registrar = attrs.get("registrar", "")
    creation_date = attrs.get("creation_date", "")
    
    # Popularity ranks
    popularity = attrs.get("popularity_ranks", {})
    
    return json.dumps({
        "domain": domain,
        "reputation": attrs.get("reputation", 0),
        "analysis_stats": {
            "malicious": analysis_stats.get("malicious", 0),
            "suspicious": analysis_stats.get("suspicious", 0),
            "harmless": analysis_stats.get("harmless", 0),
            "undetected": analysis_stats.get("undetected", 0)
        },
        "categories": list(set(categories.values())) if categories else [],
        "tags": attrs.get("tags", []),
        "dns_records": dns_records,
        "whois": {
            "registrar": registrar,
            "creation_date": creation_date,
            "whois_date": whois_date,
            "raw": whois[:1000] if whois else ""
        },
        "popularity_ranks": popularity,
        "last_analysis_date": attrs.get("last_analysis_date", ""),
        "last_modification_date": attrs.get("last_modification_date", "")
    }, indent=2)


@tool
def virustotal_ip_analysis(ip_address: str) -> str:
    """
    Get comprehensive IP address analysis from VirusTotal.
    
    Returns detailed information including:
    - IP reputation and detection statistics
    - Geolocation data
    - ASN and network information
    - Associated domains
    - SSL certificates
    - Historical data
    
    Args:
        ip_address: The IP address to analyze
    
    Returns:
        JSON string with comprehensive IP analysis
    """
    endpoint = f"ip_addresses/{ip_address}"
    result = _make_vt_request(endpoint)
    
    if "error" in result:
        return json.dumps(result)
    
    data = result.get("data", {})
    attrs = data.get("attributes", {})
    
    analysis_stats = attrs.get("last_analysis_stats", {})
    
    return json.dumps({
        "ip_address": ip_address,
        "reputation": attrs.get("reputation", 0),
        "analysis_stats": {
            "malicious": analysis_stats.get("malicious", 0),
            "suspicious": analysis_stats.get("suspicious", 0),
            "harmless": analysis_stats.get("harmless", 0),
            "undetected": analysis_stats.get("undetected", 0)
        },
        "network": {
            "asn": attrs.get("asn", ""),
            "as_owner": attrs.get("as_owner", ""),
            "network": attrs.get("network", "")
        },
        "geolocation": {
            "country": attrs.get("country", ""),
            "continent": attrs.get("continent", "")
        },
        "tags": attrs.get("tags", []),
        "last_analysis_date": attrs.get("last_analysis_date", ""),
        "whois": attrs.get("whois", "")[:500] if attrs.get("whois") else ""
    }, indent=2)


@tool
def virustotal_resolutions(domain_or_ip: str, entity_type: str = "domain", max_results: int = 50) -> str:
    """
    Get DNS resolution history (passive DNS) from VirusTotal.
    
    For domains: Returns historical IP addresses the domain has resolved to.
    For IPs: Returns domains that have resolved to this IP address.
    
    This is valuable for:
    - Tracking infrastructure changes
    - Identifying shared hosting
    - Discovering related domains
    - Historical analysis
    
    Args:
        domain_or_ip: The domain or IP address to query
        entity_type: Either "domain" or "ip" to specify the input type
        max_results: Maximum number of resolutions to return (default 50)
    
    Returns:
        JSON string with resolution history
    """
    max_results = min(max(1, max_results), 200)
    
    if entity_type == "domain":
        endpoint = f"domains/{domain_or_ip}/resolutions"
    else:
        endpoint = f"ip_addresses/{domain_or_ip}/resolutions"
    
    params = {"limit": min(max_results, 40)}
    
    all_resolutions = []
    cursor = None
    
    while len(all_resolutions) < max_results:
        if cursor:
            params["cursor"] = cursor
        
        result = _make_vt_request(endpoint, params)
        
        if "error" in result:
            if all_resolutions:
                break
            return json.dumps(result)
        
        data = result.get("data", [])
        if not data:
            break
        
        for item in data:
            attrs = item.get("attributes", {})
            all_resolutions.append({
                "resolved_to": attrs.get("ip_address") if entity_type == "domain" else attrs.get("host_name"),
                "date": attrs.get("date", ""),
                "resolver": attrs.get("resolver", "")
            })
        
        cursor = result.get("meta", {}).get("cursor")
        if not cursor or len(all_resolutions) >= max_results:
            break
        
        time.sleep(0.5)
    
    return json.dumps({
        "query": domain_or_ip,
        "type": entity_type,
        "resolution_count": len(all_resolutions),
        "resolutions": all_resolutions[:max_results]
    }, indent=2)


@tool
def virustotal_url_scan(url: str) -> str:
    """
    Analyze a URL using VirusTotal for security threats.
    
    Checks the URL against 70+ security vendors to detect:
    - Phishing pages
    - Malware distribution
    - Suspicious content
    - Known threats
    
    Args:
        url: The URL to scan (e.g., 'https://example.com/page')
    
    Returns:
        JSON string with URL analysis results
    """
    import base64
    
    # URL ID is base64 encoded URL without padding
    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    
    endpoint = f"urls/{url_id}"
    result = _make_vt_request(endpoint)
    
    if "error" in result and result.get("status") == 404:
        # URL not in VT database, need to submit for scanning
        return json.dumps({
            "url": url,
            "status": "not_found",
            "message": "URL not in VirusTotal database. It may need to be submitted for scanning.",
            "note": "Consider using the VirusTotal web interface to submit this URL for analysis."
        })
    
    if "error" in result:
        return json.dumps(result)
    
    data = result.get("data", {})
    attrs = data.get("attributes", {})
    
    analysis_stats = attrs.get("last_analysis_stats", {})
    
    # Get specific detections
    analysis_results = attrs.get("last_analysis_results", {})
    detections = []
    for vendor, details in analysis_results.items():
        if details.get("category") in ["malicious", "suspicious", "phishing"]:
            detections.append({
                "vendor": vendor,
                "category": details.get("category"),
                "result": details.get("result", "")
            })
    
    return json.dumps({
        "url": url,
        "final_url": attrs.get("last_final_url", url),
        "analysis_stats": {
            "malicious": analysis_stats.get("malicious", 0),
            "suspicious": analysis_stats.get("suspicious", 0),
            "harmless": analysis_stats.get("harmless", 0),
            "undetected": analysis_stats.get("undetected", 0)
        },
        "threat_names": attrs.get("threat_names", []),
        "categories": attrs.get("categories", {}),
        "detections": detections[:20],
        "last_analysis_date": attrs.get("last_analysis_date", ""),
        "times_submitted": attrs.get("times_submitted", 0),
        "reputation": attrs.get("reputation", 0)
    }, indent=2)


@tool
def virustotal_file_hash(file_hash: str) -> str:
    """
    Analyze a file hash using VirusTotal for malware detection.
    
    Checks the file hash against 70+ antivirus engines to identify:
    - Known malware
    - Potentially unwanted programs (PUP)
    - Adware
    - Suspicious files
    
    Supports MD5, SHA-1, and SHA-256 hashes.
    
    Args:
        file_hash: The file hash to analyze (MD5, SHA-1, or SHA-256)
    
    Returns:
        JSON string with file analysis results
    """
    endpoint = f"files/{file_hash}"
    result = _make_vt_request(endpoint)
    
    if "error" in result:
        return json.dumps(result)
    
    data = result.get("data", {})
    attrs = data.get("attributes", {})
    
    analysis_stats = attrs.get("last_analysis_stats", {})
    
    # Get specific detections
    analysis_results = attrs.get("last_analysis_results", {})
    detections = []
    for vendor, details in analysis_results.items():
        if details.get("category") == "malicious":
            detections.append({
                "vendor": vendor,
                "result": details.get("result", "")
            })
    
    # File metadata
    pe_info = attrs.get("pe_info", {})
    signature_info = attrs.get("signature_info", {})
    
    return json.dumps({
        "file_hash": file_hash,
        "sha256": attrs.get("sha256", ""),
        "sha1": attrs.get("sha1", ""),
        "md5": attrs.get("md5", ""),
        "file_name": attrs.get("meaningful_name", attrs.get("names", ["Unknown"])[0] if attrs.get("names") else "Unknown"),
        "file_type": attrs.get("type_description", ""),
        "file_size": attrs.get("size", 0),
        "analysis_stats": {
            "malicious": analysis_stats.get("malicious", 0),
            "suspicious": analysis_stats.get("suspicious", 0),
            "harmless": analysis_stats.get("harmless", 0),
            "undetected": analysis_stats.get("undetected", 0)
        },
        "threat_label": attrs.get("popular_threat_classification", {}).get("suggested_threat_label", ""),
        "detections": detections[:30],
        "first_seen": attrs.get("first_submission_date", ""),
        "last_seen": attrs.get("last_analysis_date", ""),
        "times_submitted": attrs.get("times_submitted", 0),
        "tags": attrs.get("tags", [])
    }, indent=2)


@tool
def virustotal_ssl_certificates(domain: str, max_results: int = 20) -> str:
    """
    Get SSL/TLS certificates associated with a domain from VirusTotal.
    
    Certificate transparency logs provide:
    - Historical certificates
    - Certificate issuers
    - Validity periods
    - Subject alternative names (SANs) - useful for subdomain discovery
    
    Args:
        domain: The domain to get certificates for
        max_results: Maximum number of certificates to return (default 20)
    
    Returns:
        JSON string with certificate information
    """
    endpoint = f"domains/{domain}/historical_ssl_certificates"
    params = {"limit": min(max_results, 40)}
    
    result = _make_vt_request(endpoint, params)
    
    if "error" in result:
        return json.dumps(result)
    
    certificates = []
    for item in result.get("data", [])[:max_results]:
        attrs = item.get("attributes", {})
        
        # Extract SANs for subdomain discovery
        sans = []
        extensions = attrs.get("extensions", {})
        san_data = extensions.get("subject_alternative_name", [])
        if isinstance(san_data, list):
            sans = san_data
        
        certificates.append({
            "thumbprint": attrs.get("thumbprint", ""),
            "serial_number": attrs.get("serial_number", ""),
            "issuer": attrs.get("issuer", {}).get("CN", ""),
            "subject": attrs.get("subject", {}).get("CN", ""),
            "validity": {
                "not_before": attrs.get("validity", {}).get("not_before", ""),
                "not_after": attrs.get("validity", {}).get("not_after", "")
            },
            "subject_alternative_names": sans[:50],
            "signature_algorithm": attrs.get("signature_algorithm", "")
        })
    
    # Extract unique SANs for subdomain discovery
    all_sans = set()
    for cert in certificates:
        for san in cert.get("subject_alternative_names", []):
            if san.endswith(domain) or san.endswith(f".{domain}"):
                all_sans.add(san)
    
    return json.dumps({
        "domain": domain,
        "certificate_count": len(certificates),
        "certificates": certificates,
        "discovered_subdomains": sorted(list(all_sans)),
        "note": "Subject Alternative Names (SANs) can reveal additional subdomains"
    }, indent=2)


@tool
def virustotal_communicating_files(domain_or_ip: str, entity_type: str = "domain", max_results: int = 20) -> str:
    """
    Find files that communicate with a domain or IP according to VirusTotal.
    
    This reveals:
    - Malware that contacts this infrastructure
    - Potentially malicious files
    - Command and control relationships
    
    Useful for threat intelligence and infrastructure analysis.
    
    Args:
        domain_or_ip: The domain or IP to check
        entity_type: Either "domain" or "ip"
        max_results: Maximum files to return (default 20)
    
    Returns:
        JSON string with communicating files information
    """
    if entity_type == "domain":
        endpoint = f"domains/{domain_or_ip}/communicating_files"
    else:
        endpoint = f"ip_addresses/{domain_or_ip}/communicating_files"
    
    params = {"limit": min(max_results, 40)}
    result = _make_vt_request(endpoint, params)
    
    if "error" in result:
        return json.dumps(result)
    
    files = []
    for item in result.get("data", [])[:max_results]:
        attrs = item.get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        
        files.append({
            "sha256": attrs.get("sha256", ""),
            "file_name": attrs.get("meaningful_name", "Unknown"),
            "file_type": attrs.get("type_description", ""),
            "file_size": attrs.get("size", 0),
            "detections": {
                "malicious": stats.get("malicious", 0),
                "total": sum(stats.values()) if stats else 0
            },
            "threat_label": attrs.get("popular_threat_classification", {}).get("suggested_threat_label", ""),
            "first_seen": attrs.get("first_submission_date", ""),
            "tags": attrs.get("tags", [])[:10]
        })
    
    # Sort by detection count
    files.sort(key=lambda x: x["detections"]["malicious"], reverse=True)
    
    return json.dumps({
        "query": domain_or_ip,
        "type": entity_type,
        "file_count": len(files),
        "files": files,
        "note": "High detection counts indicate known malware communicating with this infrastructure"
    }, indent=2)


@tool
def virustotal_whois_history(domain: str) -> str:
    """
    Get historical WHOIS records for a domain from VirusTotal.
    
    Historical WHOIS data can reveal:
    - Previous owners
    - Registration changes
    - Contact information history
    - Infrastructure relationships
    
    Args:
        domain: The domain to get WHOIS history for
    
    Returns:
        JSON string with WHOIS history
    """
    endpoint = f"domains/{domain}/historical_whois"
    result = _make_vt_request(endpoint)
    
    if "error" in result:
        return json.dumps(result)
    
    records = []
    for item in result.get("data", [])[:10]:
        attrs = item.get("attributes", {})
        records.append({
            "date": attrs.get("whois_date", ""),
            "registrar": attrs.get("registrar", ""),
            "registrant": {
                "name": attrs.get("registrant_name", ""),
                "organization": attrs.get("registrant_org", ""),
                "country": attrs.get("registrant_country", ""),
                "email": attrs.get("registrant_email", "")
            },
            "name_servers": attrs.get("name_servers", []),
            "creation_date": attrs.get("creation_date", ""),
            "expiration_date": attrs.get("expiration_date", "")
        })
    
    return json.dumps({
        "domain": domain,
        "record_count": len(records),
        "whois_history": records
    }, indent=2)
