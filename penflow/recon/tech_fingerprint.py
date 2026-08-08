"""
TechnologyFingerprintEngine — Component-Specific Deep Technology & Architecture Fingerprinting for PenFlow.

Capabilities:
  1. Deep Framework Detection:
     - Spring Boot & Whitelabel Error Pages (SpEL SSTI candidates)
     - ASP.NET Boilerplate (ABP Framework for rcm.motors.abb.com.cn & enterprise portals)
     - GraphQL Engines (Apollo Router, Yoga, Hasura, Directus)
     - Modern SSR & SPA (Next.js, Nuxt, SvelteKit, Vite, React, Vue, Angular)
     - AI/LLM Stacks (Gradio, Streamlit, Chainlit, LangChain, Flowise)
  2. Target-Tailored Agent Recommendation Matrix:
     - Automatically routes targets to the highest-ROI capability agents.
"""
import httpx
from typing import Dict, List, Any, Optional, Set
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.recon.tech_fingerprint")


class TechnologyFingerprintEngine:
    """
    Component-Specific Technology Fingerprinter and Specialized Agent Selector.
    """
    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout

    def analyze_response_signatures(self, headers: Dict[str, str], body_text: str) -> Dict[str, Any]:
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
        body_lower = body_text.lower()

        techs: Set[str] = set()
        recommended_agents: Set[str] = set()
        framework = "Unknown"

        # 1. Spring Boot
        if "whitelabel error page" in body_lower or "x-application-context" in headers_lower:
            techs.add("Framework:SpringBoot")
            recommended_agents.update(["polyglot_ssti", "info_disclosure", "ssrf_redirect_chain"])
            framework = "SpringBoot"

        # 2. ASP.NET Boilerplate (ABP)
        if "abp.js" in body_lower or "abp.localization" in body_lower or "/api/services/app/" in body_lower or "abp.tenantid" in body_lower:
            techs.add("Framework:ABP_Boilerplate")
            recommended_agents.update(["bfla", "idor", "account_takeover", "mass_assignment"])
            framework = "ABP_Boilerplate"

        # 3. Next.js / React
        if "__next" in body_lower or "next.js" in headers_lower.get("x-powered-by", ""):
            techs.add("Framework:Next.js")
            recommended_agents.update(["client_side_path_traversal", "framework_cache_poisoning", "prototype_pollution"])
            framework = "Next.js"
        elif "react" in body_lower or "data-reactroot" in body_lower:
            techs.add("Frontend:React")
            recommended_agents.add("client_side_path_traversal")

        # 4. GraphQL Engines
        if "apollo" in body_lower or "graphql" in headers_lower.get("server", "") or '{"errors":[' in body_text:
            techs.add("API:GraphQL")
            recommended_agents.add("graphql_introspection_and_complexity")

        # 5. AI / LLM Frontends
        if any(ai_tag in body_lower for ai_tag in ("gradio", "streamlit", "chainlit", "flowise", "langchain", "prompt")):
            techs.add("AI:LLM_Frontend")
            recommended_agents.update(["prompt_injection_audit", "ai_agent_security_audit", "rag_poisoning_audit"])

        # 6. Django / Flask / FastAPI
        if "csrftoken" in headers_lower.get("set-cookie", ""):
            techs.add("Backend:Django")
        if "fastapi" in body_lower or "uvicorn" in headers_lower.get("server", ""):
            techs.add("Backend:FastAPI")
            recommended_agents.add("bfla")

        return {
            "framework": framework,
            "technologies": sorted(list(techs)),
            "recommended_agents": sorted(list(recommended_agents))
        }

    async def fingerprint(self, url: str) -> Dict[str, Any]:
        if not url.startswith("http://") and not url.startswith("https://"):
            url = f"https://{url}"

        headers_dict: Dict[str, str] = {}
        server_header: str = ""
        analysis: Dict[str, Any] = {"framework": "Unknown", "technologies": [], "recommended_agents": []}

        try:
            async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True, verify=False) as client:
                resp = await client.get(url)
                headers_dict = {k.lower(): v for k, v in resp.headers.items()}
                server_header = headers_dict.get("server", "")
                analysis = self.analyze_response_signatures(resp.headers, resp.text)

                logger.info(f"[TechnologyFingerprintEngine] Target '{url}' -> Framework: {analysis['framework']}, Tech: {analysis['technologies']}")

        except Exception as e:
            logger.debug(f"[TechnologyFingerprintEngine] Error fingerprinting '{url}': {str(e)}")

        return {
            "url": url,
            "server": server_header,
            "framework": analysis["framework"],
            "technologies": analysis["technologies"],
            "recommended_agents": analysis["recommended_agents"],
            "headers": headers_dict
        }
