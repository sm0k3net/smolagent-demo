"""
SearXNG Tools for OWASP Security Agent
======================================
Meta-search engine integration for privacy-focused web searches.

SearXNG is a free internet metasearch engine which aggregates results from 
various search services and databases. It provides:
- Privacy-focused searching (no tracking)
- Multiple search categories (general, images, news, IT, files, etc.)
- Access to many search engines without rate limiting
- JSON API for programmatic access

Features:
- Auto-discovery of working SearXNG instances
- Category-based searching (general, IT, files, images, news, science, etc.)
- Result filtering and ranking
- Instance health checking and failover

Public instances list: https://searx.space/
Documentation: https://docs.searxng.org/
"""

import os
import json
import time
import random
import urllib.parse
from typing import Optional, List, Dict, Any
from smolagents import tool

# Try to import requests
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

# Known public SearXNG instances (updated regularly)
# These are selected for reliability and API support
SEARXNG_INSTANCES = [
    "https://search.ononoki.org",
    "https://searx.tiekoetter.com",
    "https://search.bus-hit.me",
    "https://searx.be",
    "https://search.sapti.me",
    "https://searx.namejeff.xyz",
    "https://search.privacyguides.net",
    "https://searx.work",
    "https://search.inetol.net",
    "https://searx.divided-by-zero.eu",
    "https://searx.fmac.xyz",
    "https://searxng.ch",
    "https://searx.sev.monster",
    "https://search.hbubli.cc",
    "https://darmarit.org/searx",
    "https://searx.oakleycord.dev",
    "https://s.zhaocloud.net",
    "https://etsi.me",
    "https://searx.tuxcloud.net",
    "https://search.mdosch.de",
]

# Instance health cache to avoid checking dead instances
_instance_cache: Dict[str, Dict[str, Any]] = {}
_cache_ttl = 300  # 5 minutes

# SearXNG search categories
SEARCH_CATEGORIES = {
    "general": "General web search",
    "images": "Image search",
    "videos": "Video search",
    "news": "News articles",
    "it": "IT/Tech focused results",
    "files": "File downloads",
    "science": "Scientific/academic content",
    "social_media": "Social media results",
    "music": "Music search",
    "map": "Map/location search",
}


def _check_instance_health(instance_url: str, timeout: int = 5) -> bool:
    """Check if a SearXNG instance is healthy and supports JSON API."""
    if not HAS_REQUESTS:
        return False
    
    # Check cache first
    cache_key = instance_url
    if cache_key in _instance_cache:
        cached = _instance_cache[cache_key]
        if time.time() - cached["timestamp"] < _cache_ttl:
            return cached["healthy"]
    
    try:
        # Try to access the instance with a simple search
        test_url = f"{instance_url}/search"
        params = {
            "q": "test",
            "format": "json",
            "categories": "general",
        }
        response = requests.get(
            test_url,
            params=params,
            timeout=timeout,
            headers={"User-Agent": "OWASP-Security-Agent/1.0"}
        )
        
        is_healthy = response.status_code == 200 and "results" in response.text
        
        # Cache the result
        _instance_cache[cache_key] = {
            "healthy": is_healthy,
            "timestamp": time.time(),
            "response_time": response.elapsed.total_seconds()
        }
        
        return is_healthy
        
    except Exception:
        _instance_cache[cache_key] = {
            "healthy": False,
            "timestamp": time.time(),
            "response_time": None
        }
        return False


def _find_working_instance(max_attempts: int = 5) -> Optional[str]:
    """Find a working SearXNG instance from the known list."""
    # First, check cached healthy instances
    healthy_cached = [
        url for url, cache in _instance_cache.items()
        if cache.get("healthy") and time.time() - cache["timestamp"] < _cache_ttl
    ]
    
    if healthy_cached:
        # Sort by response time and pick the fastest
        healthy_cached.sort(key=lambda x: _instance_cache[x].get("response_time", 999))
        return healthy_cached[0]
    
    # Try random instances from the list
    instances_to_try = random.sample(SEARXNG_INSTANCES, min(max_attempts, len(SEARXNG_INSTANCES)))
    
    for instance in instances_to_try:
        if _check_instance_health(instance):
            return instance
    
    # If all random attempts failed, try all instances
    for instance in SEARXNG_INSTANCES:
        if instance not in instances_to_try and _check_instance_health(instance):
            return instance
    
    return None


def _perform_search(
    query: str,
    instance_url: str,
    categories: str = "general",
    engines: Optional[str] = None,
    language: str = "en",
    pageno: int = 1,
    time_range: Optional[str] = None,
    safesearch: int = 0
) -> Dict[str, Any]:
    """Perform a search on a SearXNG instance."""
    if not HAS_REQUESTS:
        return {"error": "requests library not installed"}
    
    search_url = f"{instance_url}/search"
    
    params = {
        "q": query,
        "format": "json",
        "categories": categories,
        "language": language,
        "pageno": pageno,
        "safesearch": safesearch,
    }
    
    if engines:
        params["engines"] = engines
    
    if time_range:
        params["time_range"] = time_range  # day, week, month, year
    
    try:
        response = requests.get(
            search_url,
            params=params,
            timeout=15,
            headers={
                "User-Agent": "OWASP-Security-Agent/1.0",
                "Accept": "application/json"
            }
        )
        
        if response.status_code == 200:
            return response.json()
        else:
            return {"error": f"HTTP {response.status_code}", "details": response.text[:500]}
            
    except requests.exceptions.Timeout:
        return {"error": "Request timeout"}
    except requests.exceptions.RequestException as e:
        return {"error": f"Request failed: {str(e)}"}
    except json.JSONDecodeError:
        return {"error": "Invalid JSON response"}


@tool
def searxng_search(
    query: str,
    category: str = "general",
    max_results: int = 10,
    time_range: str = ""
) -> str:
    """
    Search the web using SearXNG meta-search engine for privacy-focused results.
    
    Automatically finds a working SearXNG instance and performs the search.
    This is useful for:
    - General web research
    - Finding security documentation
    - Looking up vulnerabilities
    - Researching targets (OSINT)
    - Finding technical resources
    
    Args:
        query: The search query string
        category: Search category - one of: general, images, videos, news, it, files, science, social_media
        max_results: Maximum number of results to return (default 10, max 50)
        time_range: Time filter - empty for all time, or: day, week, month, year
    
    Returns:
        JSON string with search results including titles, URLs, and snippets
    """
    if not HAS_REQUESTS:
        return json.dumps({"error": "requests library not installed. Run: pip install requests"})
    
    # Validate category
    valid_categories = list(SEARCH_CATEGORIES.keys())
    if category not in valid_categories:
        category = "general"
    
    # Validate max_results
    max_results = min(max(1, max_results), 50)
    
    # Find a working instance
    instance = _find_working_instance()
    if not instance:
        return json.dumps({
            "error": "No working SearXNG instance found",
            "suggestion": "All known instances are currently unavailable. Try again later."
        })
    
    # Perform the search
    results = _perform_search(
        query=query,
        instance_url=instance,
        categories=category,
        time_range=time_range if time_range else None
    )
    
    if "error" in results:
        # Try another instance
        _instance_cache[instance] = {"healthy": False, "timestamp": time.time()}
        instance = _find_working_instance()
        if instance:
            results = _perform_search(
                query=query,
                instance_url=instance,
                categories=category,
                time_range=time_range if time_range else None
            )
    
    if "error" in results:
        return json.dumps(results)
    
    # Format results
    formatted_results = []
    for r in results.get("results", [])[:max_results]:
        formatted_results.append({
            "title": r.get("title", ""),
            "url": r.get("url", ""),
            "snippet": r.get("content", "")[:500],
            "engine": r.get("engine", ""),
            "score": r.get("score", 0)
        })
    
    return json.dumps({
        "instance": instance,
        "query": query,
        "category": category,
        "total_results": len(results.get("results", [])),
        "results": formatted_results,
        "suggestions": results.get("suggestions", []),
        "corrections": results.get("corrections", [])
    }, indent=2)


@tool
def searxng_security_search(
    query: str,
    search_type: str = "vulnerability"
) -> str:
    """
    Specialized security-focused search using SearXNG.
    
    Optimized for finding security-related information including:
    - CVE details and exploits
    - Security advisories
    - Penetration testing techniques
    - Tool documentation
    - Bug bounty writeups
    
    Args:
        query: The security-related search query
        search_type: Type of security search - one of:
            - vulnerability: CVEs, exploits, security advisories
            - pentest: Penetration testing techniques and tools
            - malware: Malware analysis and threat intelligence
            - forensics: Digital forensics resources
            - ctf: CTF writeups and challenges
            - bugbounty: Bug bounty reports and methodologies
    
    Returns:
        JSON string with security-focused search results
    """
    if not HAS_REQUESTS:
        return json.dumps({"error": "requests library not installed. Run: pip install requests"})
    
    # Build optimized query based on search type
    search_modifiers = {
        "vulnerability": "CVE OR exploit OR vulnerability OR advisory",
        "pentest": "penetration testing OR pentest OR security assessment OR red team",
        "malware": "malware analysis OR threat intelligence OR IOC OR indicators of compromise",
        "forensics": "digital forensics OR incident response OR memory forensics OR disk forensics",
        "ctf": "CTF writeup OR capture the flag OR security challenge",
        "bugbounty": "bug bounty OR responsible disclosure OR security report OR HackerOne OR Bugcrowd"
    }
    
    modifier = search_modifiers.get(search_type, search_modifiers["vulnerability"])
    enhanced_query = f"{query} ({modifier})"
    
    # Find working instance
    instance = _find_working_instance()
    if not instance:
        return json.dumps({"error": "No working SearXNG instance found"})
    
    # Use IT category for technical results
    results = _perform_search(
        query=enhanced_query,
        instance_url=instance,
        categories="it",
        engines="google,bing,duckduckgo,github,stackoverflow"
    )
    
    if "error" in results:
        return json.dumps(results)
    
    # Format and categorize results
    formatted_results = []
    for r in results.get("results", [])[:15]:
        url = r.get("url", "")
        
        # Categorize by source
        source_type = "other"
        if "github.com" in url:
            source_type = "github"
        elif "exploit-db" in url or "packetstorm" in url:
            source_type = "exploit"
        elif "cve.mitre" in url or "nvd.nist" in url:
            source_type = "cve"
        elif "hackerone" in url or "bugcrowd" in url:
            source_type = "bugbounty"
        elif "stackoverflow" in url or "stackexchange" in url:
            source_type = "qa"
        
        formatted_results.append({
            "title": r.get("title", ""),
            "url": url,
            "snippet": r.get("content", "")[:400],
            "source_type": source_type,
            "engine": r.get("engine", "")
        })
    
    return json.dumps({
        "query": query,
        "search_type": search_type,
        "enhanced_query": enhanced_query,
        "results": formatted_results,
        "suggestions": results.get("suggestions", [])
    }, indent=2)


@tool
def searxng_find_instances() -> str:
    """
    Find and test available SearXNG instances.
    
    This tool checks the health of known SearXNG instances and returns
    a list of working ones sorted by response time.
    
    Useful for:
    - Debugging search issues
    - Finding the fastest available instance
    - Checking instance availability
    
    Returns:
        JSON string with list of working instances and their status
    """
    if not HAS_REQUESTS:
        return json.dumps({"error": "requests library not installed"})
    
    working = []
    failed = []
    
    for instance in SEARXNG_INSTANCES[:10]:  # Test first 10
        start_time = time.time()
        is_healthy = _check_instance_health(instance, timeout=5)
        response_time = time.time() - start_time
        
        if is_healthy:
            working.append({
                "url": instance,
                "response_time_ms": round(response_time * 1000, 2),
                "status": "healthy"
            })
        else:
            failed.append({
                "url": instance,
                "status": "unavailable"
            })
    
    # Sort working instances by response time
    working.sort(key=lambda x: x["response_time_ms"])
    
    return json.dumps({
        "working_instances": working,
        "failed_instances": failed,
        "total_tested": len(SEARXNG_INSTANCES[:10]),
        "recommendation": working[0]["url"] if working else "No working instances found"
    }, indent=2)


@tool  
def searxng_dork_search(
    target: str,
    dork_type: str = "general"
) -> str:
    """
    Perform Google dork-style searches using SearXNG for OSINT and reconnaissance.
    
    This tool constructs specialized search queries (dorks) to find:
    - Exposed sensitive files
    - Login pages and admin panels
    - Directory listings
    - Configuration files
    - Database dumps
    - Subdomains and related infrastructure
    
    Args:
        target: The target domain or organization name
        dork_type: Type of dork search - one of:
            - general: General information about the target
            - sensitive_files: Look for exposed sensitive files
            - login_pages: Find login and admin pages
            - directories: Find directory listings
            - subdomains: Discover subdomains
            - documents: Find public documents (PDF, DOC, XLS)
            - config_files: Find exposed config files
            - databases: Find database-related exposures
    
    Returns:
        JSON string with dork search results
    """
    if not HAS_REQUESTS:
        return json.dumps({"error": "requests library not installed"})
    
    # Define dork patterns
    dork_patterns = {
        "general": f'site:{target}',
        "sensitive_files": f'site:{target} (filetype:env OR filetype:log OR filetype:sql OR filetype:bak OR filetype:old)',
        "login_pages": f'site:{target} (inurl:login OR inurl:admin OR inurl:signin OR inurl:auth OR intitle:"login")',
        "directories": f'site:{target} (intitle:"index of" OR intitle:"directory listing")',
        "subdomains": f'site:*.{target} -www',
        "documents": f'site:{target} (filetype:pdf OR filetype:doc OR filetype:docx OR filetype:xls OR filetype:xlsx OR filetype:ppt)',
        "config_files": f'site:{target} (filetype:xml OR filetype:conf OR filetype:cfg OR filetype:ini OR filetype:json) -github.com',
        "databases": f'site:{target} (filetype:sql OR inurl:phpmyadmin OR inurl:mysql OR "database" filetype:txt)'
    }
    
    dork_query = dork_patterns.get(dork_type, dork_patterns["general"])
    
    # Find working instance
    instance = _find_working_instance()
    if not instance:
        return json.dumps({"error": "No working SearXNG instance found"})
    
    results = _perform_search(
        query=dork_query,
        instance_url=instance,
        categories="general"
    )
    
    if "error" in results:
        return json.dumps(results)
    
    # Format results
    formatted_results = []
    for r in results.get("results", [])[:20]:
        url = r.get("url", "")
        title = r.get("title", "")
        
        # Assess potential severity
        severity = "info"
        if any(x in url.lower() or x in title.lower() for x in ['.env', '.sql', 'password', 'backup', '.bak']):
            severity = "high"
        elif any(x in url.lower() for x in ['admin', 'login', 'phpmyadmin', 'config']):
            severity = "medium"
        elif 'index of' in title.lower():
            severity = "medium"
        
        formatted_results.append({
            "title": title,
            "url": url,
            "snippet": r.get("content", "")[:300],
            "severity": severity
        })
    
    # Sort by severity
    severity_order = {"high": 0, "medium": 1, "info": 2}
    formatted_results.sort(key=lambda x: severity_order.get(x["severity"], 3))
    
    return json.dumps({
        "target": target,
        "dork_type": dork_type,
        "query_used": dork_query,
        "results_count": len(formatted_results),
        "results": formatted_results,
        "note": "Always verify findings manually and respect robots.txt and terms of service"
    }, indent=2)
