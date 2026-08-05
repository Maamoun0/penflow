import httpx
from typing import Dict, List, Any, Optional
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.recon.tech_fingerprint")

class TechnologyFingerprintEngine:
    """
    Identifies web technologies, WAFs, CDNs, frameworks, and web servers from HTTP headers and HTML structure.
    """
    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout

    async def fingerprint(self, url: str) -> Dict[str, Any]:
        if not url.startswith("http://") and not url.startswith("https://"):
            url = f"https://{url}"

        technologies: List[str] = []
        headers_dict: Dict[str, str] = {}
        server_header: str = ""
        waf_detected: Optional[str] = None
        cdn_detected: Optional[str] = None

        try:
            async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True, verify=False) as client:
                resp = await client.get(url)
                headers_dict = {k.lower(): v for k, v in resp.headers.items()}
                server_header = headers_dict.get("server", "")

                if server_header:
                    technologies.append(f"Server:{server_header}")

                # Server / Tech Detection
                if "x-powered-by" in headers_dict:
                    technologies.append(f"PoweredBy:{headers_dict['x-powered-by']}")

                # CDN Detection
                if "cloudflare" in server_header.lower() or "cf-ray" in headers_dict:
                    cdn_detected = "Cloudflare"
                    technologies.append("CDN:Cloudflare")
                elif "akamai" in server_header.lower() or "x-akamai-transformed" in headers_dict:
                    cdn_detected = "Akamai"
                    technologies.append("CDN:Akamai")

                # WAF Detection
                if "x-cdn" in headers_dict or "incap-ses" in headers_dict:
                    waf_detected = "Imperva/Incapsula"
                    technologies.append("WAF:Imperva")
                elif "cf-mitigated" in headers_dict:
                    waf_detected = "Cloudflare WAF"
                    technologies.append("WAF:Cloudflare")

                # Framework HTML detection
                html_text = resp.text.lower()
                if "react" in html_text or "data-reactroot" in html_text:
                    technologies.append("Frontend:React")
                if "vue" in html_text or "data-v-" in html_text:
                    technologies.append("Frontend:Vue.js")
                if "next.js" in html_text or "__next" in html_text:
                    technologies.append("Framework:Next.js")
                if "wp-content" in html_text:
                    technologies.append("CMS:WordPress")

                logger.info(f"[TechnologyFingerprintEngine] Fingerprinted '{url}': Technologies={technologies}")

        except Exception as e:
            logger.debug(f"[TechnologyFingerprintEngine] Error fingerprinting '{url}': {str(e)}")

        return {
            "url": url,
            "server": server_header,
            "cdn": cdn_detected,
            "waf": waf_detected,
            "technologies": technologies,
            "headers": headers_dict
        }
