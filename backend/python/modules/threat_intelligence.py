"""
Threat Intelligence Module - Enterprise Grade
Multi-source threat intelligence aggregation and analysis
"""

import requests
import json
import hashlib
import base64
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Union
from dataclasses import dataclass, asdict
import asyncio
import aiohttp
from concurrent.futures import ThreadPoolExecutor
import ipaddress
import dns.resolver
import whois
from urllib.parse import urlparse
import geoip2.database
import geoip2.errors
from pathlib import Path
import structlog

logger = structlog.get_logger()

@dataclass
class ThreatIndicator:
    """Standardized threat indicator"""
    indicator: str
    indicator_type: str
    confidence: float
    severity: str
    first_seen: datetime
    last_seen: datetime
    tags: List[str]
    sources: List[str]
    context: Dict
    ttl: int = 86400  # Time to live in seconds

@dataclass
class ThreatIntelReport:
    """Comprehensive threat intelligence report"""
    indicator: str
    indicator_type: str
    reputation_score: float
    threat_types: List[str]
    malware_families: List[str]
    sources: Dict
    enrichment: Dict
    recommendations: List[str]
    iocs: List[ThreatIndicator]
    generated_at: datetime

class ThreatIntelligence:
    """Enterprise threat intelligence platform"""

    def __init__(self):
        self.api_keys = self._load_api_keys()
        self.sources = {
            'virustotal': VirusTotalIntel(self.api_keys.get('virustotal')),
            'shodan': ShodanIntel(self.api_keys.get('shodan')),
            'greynoise': GreyNoiseIntel(self.api_keys.get('greynoise')),
            'censys': CensysIntel(self.api_keys.get('censys')),
            'alienvault': AlienVaultIntel(),
            'abuse_ch': AbuseCHIntel(),
            'urlvoid': URLVoidIntel(self.api_keys.get('urlvoid')),
            'hybrid_analysis': HybridAnalysisIntel(self.api_keys.get('hybrid_analysis'))
        }
        self.geoip_db_path = Path('databases/GeoLite2-City.mmdb')
        self.cache = {}
        self.rate_limits = {}

    def _load_api_keys(self):
        """Load API keys from environment or config"""
        import os
        return {
            'virustotal': os.getenv('VIRUSTOTAL_API_KEY'),
            'shodan': os.getenv('SHODAN_API_KEY'),
            'greynoise': os.getenv('GREYNOISE_API_KEY'),
            'censys': {
                'id': os.getenv('CENSYS_API_ID'),
                'secret': os.getenv('CENSYS_API_SECRET')
            },
            'urlvoid': os.getenv('URLVOID_API_KEY'),
            'hybrid_analysis': os.getenv('HYBRID_ANALYSIS_API_KEY')
        }

    async def analyze_indicator(self, indicator: str, indicator_type: str,
                              include_context: bool = True) -> ThreatIntelReport:
        """Comprehensive threat indicator analysis"""

        # Validate and normalize indicator
        normalized_indicator = self._normalize_indicator(indicator, indicator_type)

        # Check cache first
        cache_key = f"{normalized_indicator}:{indicator_type}"
        if cache_key in self.cache:
            cached_result = self.cache[cache_key]
            if datetime.now() - cached_result['timestamp'] < timedelta(hours=1):
                return cached_result['data']

        logger.info("threat_analysis_started",
                   indicator=normalized_indicator,
                   type=indicator_type)

        # Gather intelligence from multiple sources
        source_results = await self._gather_from_sources(
            normalized_indicator, indicator_type
        )

        # Enrich with additional context
        enrichment = {}
        if include_context:
            enrichment = await self._enrich_indicator(
                normalized_indicator, indicator_type
            )

        # Aggregate and analyze results
        report = self._generate_report(
            normalized_indicator,
            indicator_type,
            source_results,
            enrichment
        )

        # Cache result
        self.cache[cache_key] = {
            'data': report,
            'timestamp': datetime.now()
        }

        logger.info("threat_analysis_completed",
                   indicator=normalized_indicator,
                   reputation_score=report.reputation_score)

        return report

    async def _gather_from_sources(self, indicator: str, indicator_type: str) -> Dict:
        """Gather intelligence from multiple sources asynchronously"""

        tasks = []
        active_sources = self._get_active_sources(indicator_type)

        async with aiohttp.ClientSession() as session:
            for source_name in active_sources:
                source = self.sources[source_name]
                if self._check_rate_limit(source_name):
                    task = source.lookup(session, indicator, indicator_type)
                    tasks.append((source_name, task))

        results = {}
        completed_tasks = await asyncio.gather(
            *[task for _, task in tasks],
            return_exceptions=True
        )

        for i, result in enumerate(completed_tasks):
            source_name = tasks[i][0]
            if isinstance(result, Exception):
                logger.error("source_lookup_failed",
                           source=source_name,
                           error=str(result))
                results[source_name] = {'error': str(result)}
            else:
                results[source_name] = result
                self._update_rate_limit(source_name)

        return results

    def _get_active_sources(self, indicator_type: str) -> List[str]:
        """Get active sources based on indicator type"""
        source_mapping = {
            'ip': ['virustotal', 'shodan', 'greynoise', 'censys', 'alienvault', 'abuse_ch'],
            'domain': ['virustotal', 'urlvoid', 'alienvault', 'abuse_ch'],
            'url': ['virustotal', 'urlvoid', 'hybrid_analysis'],
            'hash': ['virustotal', 'hybrid_analysis', 'alienvault'],
            'email': ['abuse_ch'],
            'file': ['virustotal', 'hybrid_analysis']
        }

        return source_mapping.get(indicator_type, [])

    def _check_rate_limit(self, source: str) -> bool:
        """Check if source is within rate limits"""
        if source not in self.rate_limits:
            return True

        last_request = self.rate_limits[source]['last_request']
        min_interval = self.rate_limits[source]['min_interval']

        return time.time() - last_request >= min_interval

    def _update_rate_limit(self, source: str):
        """Update rate limit tracking"""
        self.rate_limits[source] = {
            'last_request': time.time(),
            'min_interval': 1.0  # Default 1 second between requests
        }

    async def _enrich_indicator(self, indicator: str, indicator_type: str) -> Dict:
        """Enrich indicator with additional context"""
        enrichment = {}

        if indicator_type == 'ip':
            enrichment.update(await self._enrich_ip(indicator))
        elif indicator_type == 'domain':
            enrichment.update(await self._enrich_domain(indicator))
        elif indicator_type == 'url':
            enrichment.update(await self._enrich_url(indicator))
        elif indicator_type == 'hash':
            enrichment.update(await self._enrich_hash(indicator))

        return enrichment

    async def _enrich_ip(self, ip: str) -> Dict:
        """Enrich IP address with geolocation and additional data"""
        enrichment = {}

        # Geolocation
        try:
            if self.geoip_db_path.exists():
                with geoip2.database.Reader(str(self.geoip_db_path)) as reader:
                    response = reader.city(ip)
                    enrichment['geolocation'] = {
                        'country': response.country.name,
                        'country_code': response.country.iso_code,
                        'city': response.city.name,
                        'region': response.subdivisions.most_specific.name,
                        'latitude': float(response.location.latitude) if response.location.latitude else None,
                        'longitude': float(response.location.longitude) if response.location.longitude else None,
                        'accuracy_radius': response.location.accuracy_radius
                    }
        except (geoip2.errors.AddressNotFoundError, FileNotFoundError):
            enrichment['geolocation'] = {'error': 'Location not found'}

        # Reverse DNS
        try:
            import socket
            hostname = socket.gethostbyaddr(ip)[0]
            enrichment['reverse_dns'] = hostname
        except:
            enrichment['reverse_dns'] = None

        # ASN Information
        try:
            enrichment['asn'] = await self._get_asn_info(ip)
        except:
            enrichment['asn'] = None

        # Check if IP is in known ranges
        enrichment['ip_classification'] = self._classify_ip(ip)

        return enrichment

    async def _enrich_domain(self, domain: str) -> Dict:
        """Enrich domain with DNS and WHOIS data"""
        enrichment = {}

        # WHOIS data
        try:
            w = whois.whois(domain)
            enrichment['whois'] = {
                'registrar': w.registrar,
                'creation_date': str(w.creation_date) if w.creation_date else None,
                'expiration_date': str(w.expiration_date) if w.expiration_date else None,
                'name_servers': w.name_servers if isinstance(w.name_servers, list) else [w.name_servers] if w.name_servers else []
            }
        except Exception as e:
            enrichment['whois'] = {'error': str(e)}

        # DNS records
        try:
            dns_records = {}
            for record_type in ['A', 'AAAA', 'MX', 'NS', 'TXT']:
                try:
                    answers = dns.resolver.resolve(domain, record_type)
                    dns_records[record_type] = [str(rdata) for rdata in answers]
                except:
                    dns_records[record_type] = []

            enrichment['dns_records'] = dns_records
        except Exception as e:
            enrichment['dns_records'] = {'error': str(e)}

        # Subdomain enumeration (basic)
        enrichment['subdomains'] = await self._enumerate_subdomains(domain)

        return enrichment

    async def _enrich_url(self, url: str) -> Dict:
        """Enrich URL with structural analysis"""
        enrichment = {}

        parsed = urlparse(url)
        enrichment['parsed_url'] = {
            'scheme': parsed.scheme,
            'domain': parsed.netloc,
            'path': parsed.path,
            'params': parsed.params,
            'query': parsed.query,
            'fragment': parsed.fragment
        }

        # Analyze URL structure for suspicious patterns
        enrichment['url_analysis'] = self._analyze_url_structure(url)

        # Get domain enrichment for the host
        if parsed.netloc:
            enrichment['domain_info'] = await self._enrich_domain(parsed.netloc)

        return enrichment

    async def _enrich_hash(self, file_hash: str) -> Dict:
        """Enrich file hash with metadata"""
        enrichment = {}

        hash_length = len(file_hash)
        if hash_length == 32:
            enrichment['hash_type'] = 'MD5'
        elif hash_length == 40:
            enrichment['hash_type'] = 'SHA1'
        elif hash_length == 64:
            enrichment['hash_type'] = 'SHA256'
        else:
            enrichment['hash_type'] = 'Unknown'

        # Check hash against known good/bad lists
        enrichment['known_status'] = await self._check_known_hash_lists(file_hash)

        return enrichment

    def _generate_report(self, indicator: str, indicator_type: str,
                        source_results: Dict, enrichment: Dict) -> ThreatIntelReport:
        """Generate comprehensive threat intelligence report"""

        # Calculate reputation score
        reputation_score = self._calculate_reputation_score(source_results)

        # Aggregate threat types
        threat_types = self._aggregate_threat_types(source_results)

        # Extract malware families
        malware_families = self._extract_malware_families(source_results)

        # Generate recommendations
        recommendations = self._generate_recommendations(
            reputation_score, threat_types, indicator_type
        )

        # Extract IOCs
        iocs = self._extract_related_iocs(source_results)

        return ThreatIntelReport(
            indicator=indicator,
            indicator_type=indicator_type,
            reputation_score=reputation_score,
            threat_types=threat_types,
            malware_families=malware_families,
            sources=source_results,
            enrichment=enrichment,
            recommendations=recommendations,
            iocs=iocs,
            generated_at=datetime.now()
        )

    def _calculate_reputation_score(self, source_results: Dict) -> float:
        """Calculate overall reputation score (0-100, lower is worse)"""
        scores = []
        weights = {
            'virustotal': 0.3,
            'greynoise': 0.2,
            'shodan': 0.15,
            'alienvault': 0.15,
            'abuse_ch': 0.1,
            'censys': 0.1
        }

        total_weight = 0
        weighted_sum = 0

        for source, result in source_results.items():
            if 'error' in result:
                continue

            weight = weights.get(source, 0.05)
            score = self._extract_source_score(source, result)

            if score is not None:
                weighted_sum += score * weight
                total_weight += weight

        if total_weight > 0:
            return max(0, min(100, weighted_sum / total_weight))

        return 50  # Neutral score if no data

    def _extract_source_score(self, source: str, result: Dict) -> Optional[float]:
        """Extract reputation score from source-specific result"""
        if source == 'virustotal':
            if 'positives' in result and 'total' in result:
                return max(0, 100 - (result['positives'] / result['total'] * 100))

        elif source == 'greynoise':
            if 'malicious' in result:
                return 10 if result['malicious'] else 80

        elif source == 'alienvault':
            if 'pulse_info' in result and 'count' in result['pulse_info']:
                pulse_count = result['pulse_info']['count']
                return max(0, 100 - min(pulse_count * 10, 90))

        return None

    def _aggregate_threat_types(self, source_results: Dict) -> List[str]:
        """Aggregate threat types from all sources"""
        threat_types = set()

        for source, result in source_results.items():
            if 'error' in result:
                continue

            # Extract threat types based on source format
            if source == 'virustotal':
                if 'scans' in result:
                    for engine, scan_result in result['scans'].items():
                        if scan_result.get('detected'):
                            threat_types.add(scan_result.get('result', 'malware'))

            elif source == 'greynoise':
                if result.get('malicious'):
                    threat_types.add('scanner')
                if 'tags' in result:
                    threat_types.update(result['tags'])

            elif source == 'alienvault':
                if 'pulse_info' in result and 'pulses' in result['pulse_info']:
                    for pulse in result['pulse_info']['pulses']:
                        threat_types.update(pulse.get('tags', []))

        return list(threat_types)

    def _extract_malware_families(self, source_results: Dict) -> List[str]:
        """Extract malware family names"""
        families = set()

        for source, result in source_results.items():
            if source == 'virustotal' and 'scans' in result:
                for engine, scan_result in result['scans'].items():
                    if scan_result.get('detected'):
                        family = scan_result.get('result', '')
                        # Extract family name from detection string
                        family_name = self._extract_family_name(family)
                        if family_name:
                            families.add(family_name)

        return list(families)

    def _generate_recommendations(self, reputation_score: float,
                                threat_types: List[str], indicator_type: str) -> List[str]:
        """Generate security recommendations"""
        recommendations = []

        if reputation_score < 30:
            recommendations.append(f"CRITICAL: Block this {indicator_type} immediately")
            recommendations.append("Implement emergency response procedures")
        elif reputation_score < 50:
            recommendations.append(f"HIGH: Consider blocking this {indicator_type}")
            recommendations.append("Increase monitoring and alerting")
        elif reputation_score < 70:
            recommendations.append(f"MEDIUM: Monitor this {indicator_type} closely")
            recommendations.append("Review security policies")

        # Threat-specific recommendations
        if 'botnet' in threat_types:
            recommendations.append("Check for C&C communication patterns")
        if 'phishing' in threat_types:
            recommendations.append("Implement email security controls")
        if 'malware' in threat_types:
            recommendations.append("Scan endpoints for infections")

        return recommendations

    def _extract_related_iocs(self, source_results: Dict) -> List[ThreatIndicator]:
        """Extract related IOCs from source results"""
        iocs = []

        for source, result in source_results.items():
            if 'error' in result:
                continue

            # Extract IOCs based on source format
            if source == 'alienvault' and 'pulse_info' in result:
                for pulse in result['pulse_info'].get('pulses', []):
                    for indicator in pulse.get('indicators', []):
                        ioc = ThreatIndicator(
                            indicator=indicator.get('indicator', ''),
                            indicator_type=indicator.get('type', ''),
                            confidence=0.8,
                            severity='MEDIUM',
                            first_seen=datetime.now(),
                            last_seen=datetime.now(),
                            tags=pulse.get('tags', []),
                            sources=[source],
                            context={'pulse_id': pulse.get('id', '')}
                        )
                        iocs.append(ioc)

        return iocs

    def _normalize_indicator(self, indicator: str, indicator_type: str) -> str:
        """Normalize indicator format"""
        if indicator_type == 'ip':
            try:
                # Validate IP address
                ipaddress.ip_address(indicator)
                return indicator.strip()
            except ValueError:
                raise ValueError(f"Invalid IP address: {indicator}")

        elif indicator_type == 'domain':
            # Basic domain validation and normalization
            domain = indicator.lower().strip()
            if domain.startswith('http://') or domain.startswith('https://'):
                domain = urlparse(indicator).netloc
            return domain

        elif indicator_type == 'hash':
            # Normalize hash to uppercase
            return indicator.upper().strip()

        elif indicator_type == 'url':
            return indicator.strip()

        return indicator.strip()

    def _classify_ip(self, ip: str) -> Dict:
        """Classify IP address"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            classification = {
                'is_private': ip_obj.is_private,
                'is_loopback': ip_obj.is_loopback,
                'is_multicast': ip_obj.is_multicast,
                'is_reserved': ip_obj.is_reserved,
                'version': ip_obj.version
            }

            # Check known ranges
            if ip_obj.is_private:
                classification['type'] = 'private'
            elif str(ip_obj).startswith(('8.8.', '1.1.1.')):
                classification['type'] = 'public_dns'
            else:
                classification['type'] = 'public'

            return classification
        except ValueError:
            return {'error': 'Invalid IP address'}

    async def _get_asn_info(self, ip: str) -> Dict:
        """Get ASN information for IP"""
        # This would typically use a service like ipinfo.io or similar
        try:
            async with aiohttp.ClientSession() as session:
                url = f"https://ipinfo.io/{ip}/json"
                async with session.get(url) as response:
                    if response.status == 200:
                        data = await response.json()
                        return {
                            'asn': data.get('org', ''),
                            'isp': data.get('org', '').split(' ', 1)[1] if ' ' in data.get('org', '') else '',
                            'country': data.get('country', '')
                        }
        except:
            pass
        return {}

    async def _enumerate_subdomains(self, domain: str) -> List[str]:
        """Basic subdomain enumeration"""
        common_subdomains = ['www', 'mail', 'ftp', 'api', 'admin', 'test', 'dev']
        found_subdomains = []

        for sub in common_subdomains:
            subdomain = f"{sub}.{domain}"
            try:
                dns.resolver.resolve(subdomain, 'A')
                found_subdomains.append(subdomain)
            except:
                continue

        return found_subdomains

    def _analyze_url_structure(self, url: str) -> Dict:
        """Analyze URL for suspicious patterns"""
        analysis = {}

        # Check for suspicious patterns
        suspicious_patterns = [
            'bit.ly', 'tinyurl.com', 'goo.gl',  # URL shorteners
            'exe', 'scr', 'bat',  # Executable extensions
            'login', 'secure', 'verify'  # Phishing keywords
        ]

        analysis['suspicious_patterns'] = [
            pattern for pattern in suspicious_patterns if pattern in url.lower()
        ]

        # URL length analysis
        analysis['url_length'] = len(url)
        analysis['suspicious_length'] = len(url) > 200

        # Character analysis
        analysis['suspicious_chars'] = bool(re.search(r'[^\w\-\.\:\/\?\=\&]', url))

        return analysis

    async def _check_known_hash_lists(self, file_hash: str) -> Dict:
        """Check hash against known good/bad lists"""
        # This would check against various hash databases
        return {
            'known_good': False,
            'known_bad': False,
            'whitelist_match': None,
            'blacklist_match': None
        }

    def _extract_family_name(self, detection_string: str) -> Optional[str]:
        """Extract malware family name from detection string"""
        # Common patterns for malware family extraction
        patterns = [
            r'(\w+)\.[\w\!]+',  # Family.Variant
            r'(\w+)[\-_][\w]+',  # Family-Variant or Family_Variant
            r'^(\w+)',  # First word
        ]

        for pattern in patterns:
            match = re.search(pattern, detection_string, re.IGNORECASE)
            if match:
                family = match.group(1)
                # Filter out common prefixes
                if family.lower() not in ['trojan', 'virus', 'worm', 'adware', 'generic']:
                    return family

        return None

# Source-specific intelligence classes
class VirusTotalIntel:
    """VirusTotal threat intelligence integration"""

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = 'https://www.virustotal.com/vtapi/v2'

    async def lookup(self, session: aiohttp.ClientSession,
                    indicator: str, indicator_type: str) -> Dict:
        """Lookup indicator in VirusTotal"""
        if not self.api_key:
            return {'error': 'API key not configured'}

        endpoints = {
            'ip': 'ip-address/report',
            'domain': 'domain/report',
            'url': 'url/report',
            'hash': 'file/report'
        }

        endpoint = endpoints.get(indicator_type)
        if not endpoint:
            return {'error': f'Unsupported indicator type: {indicator_type}'}

        params = {
            'apikey': self.api_key,
            'resource' if indicator_type == 'hash' else indicator_type: indicator
        }

        try:
            async with session.get(f"{self.base_url}/{endpoint}", params=params) as response:
                return await response.json()
        except Exception as e:
            return {'error': str(e)}

class ShodanIntel:
    """Shodan threat intelligence integration"""

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = 'https://api.shodan.io'

    async def lookup(self, session: aiohttp.ClientSession,
                    indicator: str, indicator_type: str) -> Dict:
        """Lookup indicator in Shodan"""
        if not self.api_key or indicator_type != 'ip':
            return {'error': 'API key not configured or unsupported type'}

        params = {'key': self.api_key}

        try:
            async with session.get(f"{self.base_url}/shodan/host/{indicator}",
                                 params=params) as response:
                return await response.json()
        except Exception as e:
            return {'error': str(e)}

class GreyNoiseIntel:
    """GreyNoise threat intelligence integration"""

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = 'https://api.greynoise.io/v3'

    async def lookup(self, session: aiohttp.ClientSession,
                    indicator: str, indicator_type: str) -> Dict:
        """Lookup indicator in GreyNoise"""
        if not self.api_key or indicator_type != 'ip':
            return {'error': 'API key not configured or unsupported type'}

        headers = {'key': self.api_key}

        try:
            async with session.get(f"{self.base_url}/community/{indicator}",
                                 headers=headers) as response:
                return await response.json()
        except Exception as e:
            return {'error': str(e)}

class CensysIntel:
    """Censys threat intelligence integration"""

    def __init__(self, api_credentials: Dict):
        self.api_id = api_credentials.get('id') if api_credentials else None
        self.api_secret = api_credentials.get('secret') if api_credentials else None
        self.base_url = 'https://search.censys.io/api/v2'

    async def lookup(self, session: aiohttp.ClientSession,
                    indicator: str, indicator_type: str) -> Dict:
        """Lookup indicator in Censys"""
        if not self.api_id or not self.api_secret or indicator_type != 'ip':
            return {'error': 'API credentials not configured or unsupported type'}

        auth = aiohttp.BasicAuth(self.api_id, self.api_secret)

        try:
            async with session.get(f"{self.base_url}/hosts/{indicator}",
                                 auth=auth) as response:
                return await response.json()
        except Exception as e:
            return {'error': str(e)}

class AlienVaultIntel:
    """AlienVault OTX threat intelligence integration"""

    def __init__(self):
        self.base_url = 'https://otx.alienvault.com/api/v1/indicators'

    async def lookup(self, session: aiohttp.ClientSession,
                    indicator: str, indicator_type: str) -> Dict:
        """Lookup indicator in AlienVault OTX"""
        type_mapping = {
            'ip': 'IPv4',
            'domain': 'domain',
            'url': 'URL',
            'hash': 'file'
        }

        otx_type = type_mapping.get(indicator_type)
        if not otx_type:
            return {'error': f'Unsupported indicator type: {indicator_type}'}

        try:
            url = f"{self.base_url}/{otx_type}/{indicator}/general"
            async with session.get(url) as response:
                return await response.json()
        except Exception as e:
            return {'error': str(e)}

class AbuseCHIntel:
    """Abuse.ch threat intelligence integration"""

    def __init__(self):
        self.base_url = 'https://urlhaus-api.abuse.ch/v1'

    async def lookup(self, session: aiohttp.ClientSession,
                    indicator: str, indicator_type: str) -> Dict:
        """Lookup indicator in Abuse.ch"""
        if indicator_type not in ['url', 'domain', 'ip']:
            return {'error': f'Unsupported indicator type: {indicator_type}'}

        data = {indicator_type: indicator}

        try:
            async with session.post(f"{self.base_url}/payload/", data=data) as response:
                return await response.json()
        except Exception as e:
            return {'error': str(e)}

class URLVoidIntel:
    """URLVoid threat intelligence integration"""

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = 'https://api.urlvoid.com/1000'

    async def lookup(self, session: aiohttp.ClientSession,
                    indicator: str, indicator_type: str) -> Dict:
        """Lookup indicator in URLVoid"""
        if not self.api_key or indicator_type not in ['url', 'domain']:
            return {'error': 'API key not configured or unsupported type'}

        # Extract domain from URL if needed
        if indicator_type == 'url':
            indicator = urlparse(indicator).netloc

        try:
            url = f"{self.base_url}/{self.api_key}/scan/{indicator}/"
            async with session.get(url) as response:
                return await response.json()
        except Exception as e:
            return {'error': str(e)}

class HybridAnalysisIntel:
    """Hybrid Analysis threat intelligence integration"""

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = 'https://www.hybrid-analysis.com/api/v2'

    async def lookup(self, session: aiohttp.ClientSession,
                    indicator: str, indicator_type: str) -> Dict:
        """Lookup indicator in Hybrid Analysis"""
        if not self.api_key or indicator_type not in ['hash', 'url']:
            return {'error': 'API key not configured or unsupported type'}

        headers = {'api-key': self.api_key, 'User-Agent': 'CyberSec-TI'}

        try:
            if indicator_type == 'hash':
                endpoint = 'search/hash'
                data = {'hash': indicator}
            else:  # url
                endpoint = 'search/url'
                data = {'url': indicator}

            async with session.post(f"{self.base_url}/{endpoint}",
                                   headers=headers, data=data) as response:
                return await response.json()
        except Exception as e:
            return {'error': str(e)}