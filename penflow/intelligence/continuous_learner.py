"""
ContinuousLearnerDaemon — Real-time & Scheduled Background Knowledge Learning Daemon for PenFlow.

Monitors the security writeups directory ('data/writeups/') for new or modified writeups,
automatically re-mines tactical patterns, updates the ExperienceLayer, and regenerates
'config/rules/mined_rules.yaml' without interrupting active scans.
"""
import os
import time
import asyncio
from typing import Optional, Dict, Any
from penflow.intelligence.writeup_loader import WriteupIngestionEngine
from penflow.intelligence.experience_layer import ExperienceLayer
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.intelligence.continuous_learner")


from penflow.intelligence.threat_intel_harvester import ThreatIntelFeedHarvester

class ContinuousLearnerDaemon:
    """
    Background learning daemon that continuously monitors research directories
    and live public threat feeds (CISA KEV / CVEs) to re-train PenFlow's intelligence models in real-time.
    """

    def __init__(self, watch_dir: str = "data/writeups", rules_file: str = "config/rules/mined_rules.yaml", interval_seconds: float = 10.0):
        self.watch_dir = watch_dir
        self.rules_file = rules_file
        self.interval_seconds = interval_seconds
        self.ingestion_engine = WriteupIngestionEngine()
        self.harvester = ThreatIntelFeedHarvester(output_dir=watch_dir)
        self._last_modified_map: Dict[str, float] = {}
        self._is_running = False

    async def harvest_and_learn_once_async(self) -> Dict[str, Any]:
        """Harvests live online threat feeds and re-trains if changes/new writeups are detected."""
        if not os.path.exists(self.watch_dir):
            os.makedirs(self.watch_dir, exist_ok=True)

        # 1. Harvest live advisories & disclosed HackerOne reports from public feeds
        try:
            advisories = await self.harvester.harvest_all_intel_and_h1_reports(max_items=30)
            if advisories:
                self.harvester.save_advisories_as_writeups(advisories)
        except Exception as e:
            logger.debug(f"[ContinuousLearner] Live threat & H1 harvesting skipped/failed: {e}")

        # 2. Check local files and re-mine rules
        return self.check_and_learn_once()

    def check_and_learn_once(self) -> Dict[str, Any]:
        """Performs a single incremental check and re-trains if changes/new files are detected."""
        if not os.path.exists(self.watch_dir):
            os.makedirs(self.watch_dir, exist_ok=True)

        current_files = {}
        has_changes = False

        for root, _, files in os.walk(self.watch_dir):
            for file in files:
                if file.endswith((".md", ".txt")):
                    full_path = os.path.join(root, file)
                    try:
                        mtime = os.path.getmtime(full_path)
                        current_files[full_path] = mtime
                        if full_path not in self._last_modified_map or self._last_modified_map[full_path] != mtime:
                            has_changes = True
                    except OSError:
                        pass

        if len(current_files) != len(self._last_modified_map):
            has_changes = True

        if has_changes or not os.path.exists(self.rules_file):
            logger.info("[ContinuousLearner] Detected changes in writeup dataset. Executing real-time knowledge ingestion...")
            res = self.ingestion_engine.ingest_directory(self.watch_dir, rules_output_file=self.rules_file)
            self._last_modified_map = current_files
            return {"updated": True, "details": res}
        
        return {"updated": False, "details": {"ingested_count": len(current_files)}}

    async def start_daemon_loop(self):
        """Runs continuous background learning loop."""
        self._is_running = True
        logger.info(f"[ContinuousLearner] Continuous background learning daemon started. Watching '{self.watch_dir}' (Interval: {self.interval_seconds}s)...")
        print(f"\n[+] PenFlow Continuous Background Learning Daemon Active")
        print(f"    - Watching Directory: '{self.watch_dir}'")
        print(f"    - Manifest File: '{self.rules_file}'")
        print(f"    - Poll Interval: {self.interval_seconds}s\n")

        try:
            while self._is_running:
                res = await self.harvest_and_learn_once_async()
                if res["updated"]:
                    print(f"[*] Real-time Knowledge Update: Mined {res['details']['rules_generated']} rules from {res['details']['ingested_count']} writeups.")
                await asyncio.sleep(self.interval_seconds)
        except asyncio.CancelledError:
            logger.info("[ContinuousLearner] Continuous learning daemon stopped.")
            self._is_running = False

    def stop(self):
        self._is_running = False
