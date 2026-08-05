from dataclasses import dataclass, field
from typing import Dict, List, Set
import re

from penflow.network.http_client import HttpResponse
from penflow.utils.logger import get_logger

logger = get_logger("penflow.recon.tech_fingerprint")

@dataclass
class TechProfile:
    server: str = "unknown"
    frameworks: Set[str] = field(default_factory=set)
    cms: str = "unknown"
    waf: str = "unknown"
    cdn: str = "unknown"
    js_libraries: Set[str] = field(default_factory=set)
    languages: Set[str] = field(default_factory=set)

    def to_dict(self) -> dict:
        return {
            "server": self.server,
            "frameworks": list(self.frameworks),
            "cms": self.cms,
            "waf": self.waf,
            "cdn": self.cdn,
            "js_libraries": list(self.js_libraries),
            "languages": list(self.languages)
        }

class TechFingerprinter:
    def __init__(self):
        # Built-in minimal signatures (can be expanded via YAML later)
        self.signatures = {
            "headers": {
                "server": {
                    "nginx": "nginx",
                    "apache": "apache",
                    "cloudflare": "cloudflare",
                    "iis": "microsoft-iis"
                },
                "x-powered-by": {
                    "php": "php",
                    "asp.net": "asp.net",
                    "express": "express",
                    "next.js": "next.js"
                }
            },
            "cookies": {
                "PHPSESSID": "php",
                "JSESSIONID": "java",
                "ASP.NET_SessionId": "asp.net",
                "laravel_session": "laravel",
                "csrftoken": "django"
            },
            "waf": {
                "cloudflare": [r"cf-ray", r"__cfduid", r"cf-cache-status"],
                "aws_waf": [r"x-amzn-requestid", r"awselb"],
                "akamai": [r"akamai-ghost", r"x-akamai"]
            },
            "cms": {
                "wordpress": [r"/wp-content/", r"/wp-includes/"],
                "drupal": [r"Drupal.settings", r"/sites/default/files/"],
                "magento": [r"Mage.Cookies"]
            },
            "frameworks": {
                "react": [r"data-reactroot", r"__REACT_DEVTOOLS_GLOBAL_HOOK__", r"react-dom"],
                "angular": [r"ng-version", r"ng-app", r"ng-controller"],
                "vue": [r"data-v-", r"__VUE_HOT_MAP__"],
                "nextjs": [r"__NEXT_DATA__", r"/_next/"]
            }
        }

    async def fingerprint(self, url: str, response: HttpResponse) -> TechProfile:
        profile = TechProfile()
        headers_lower = {k.lower(): str(v).lower() for k, v in response.headers.items()}
        body = response.body
        
        # 1. Server Header
        if "server" in headers_lower:
            server_val = headers_lower["server"]
            for name, pattern in self.signatures["headers"]["server"].items():
                if pattern in server_val:
                    profile.server = name
                    if name == "cloudflare":
                        profile.cdn = "cloudflare"
                        profile.waf = "cloudflare"

        # 2. X-Powered-By
        if "x-powered-by" in headers_lower:
            x_powered_by = headers_lower["x-powered-by"]
            for name, pattern in self.signatures["headers"]["x-powered-by"].items():
                if pattern in x_powered_by:
                    profile.languages.add(name)

        # 3. Cookies
        if "set-cookie" in headers_lower:
            cookie_val = headers_lower["set-cookie"]
            for cookie_name, lang in self.signatures["cookies"].items():
                if cookie_name.lower() in cookie_val:
                    if lang == "laravel" or lang == "django":
                        profile.frameworks.add(lang)
                        profile.languages.add("php" if lang == "laravel" else "python")
                    else:
                        profile.languages.add(lang)

        # 4. WAF Detection via headers
        for waf_name, patterns in self.signatures["waf"].items():
            for pattern in patterns:
                # Check header keys
                if any(re.search(pattern, h) for h in headers_lower.keys()):
                    profile.waf = waf_name
                    break

        # 5. CMS Detection via body patterns
        for cms_name, patterns in self.signatures["cms"].items():
            for pattern in patterns:
                if re.search(pattern, body, re.IGNORECASE):
                    profile.cms = cms_name
                    profile.languages.add("php")
                    break

        # 6. JS Frameworks
        for fw_name, patterns in self.signatures["frameworks"].items():
            for pattern in patterns:
                if re.search(pattern, body, re.IGNORECASE):
                    profile.frameworks.add(fw_name)
                    break

        return profile
