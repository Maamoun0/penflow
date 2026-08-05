import asyncio
from typing import Dict, Any, Optional
from penflow.knowledge.knowledge_store import KnowledgeStore
from penflow.recon.target_manager import TargetManager
from penflow.recon.scope_manager import ScopeManager
from penflow.recon.asset_discovery import AssetDiscoveryEngine
from penflow.recon.change_detector import ChangeDetector, ReconChangeEvent
from penflow.recon.recon_scheduler import ReconScheduler, ReconTaskSpec
from penflow.core.event_bus import EventBus
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.recon.pipeline")

class ReconPipeline:
    """
    Event-driven continuous Reconnaissance Pipeline orchestrating:
    Observation -> Knowledge Store -> Change Detection -> Event -> Scheduler -> New Recon Task
    """
    def __init__(self, knowledge_store: KnowledgeStore, event_bus: Optional[EventBus] = None):
        self.knowledge = knowledge_store
        self.event_bus = event_bus or EventBus()
        self.target_manager = TargetManager()
        self.scope_manager = ScopeManager()
        self.asset_discovery = AssetDiscoveryEngine(self.knowledge, self.scope_manager)
        self.change_detector = ChangeDetector()
        self.recon_scheduler = ReconScheduler()

    async def process_observation(self, asset: str, obs_type: str, data: Dict[str, Any]) -> Optional[ReconTaskSpec]:
        asset_clean = asset.strip().lower()

        # Step 1: Scope validation & Knowledge Store insertion
        if not self.scope_manager.is_in_scope(asset_clean):
            logger.info(f"[ReconPipeline] Asset '{asset_clean}' out of scope. Skipping.")
            return None

        self.knowledge.observations.record_observation(asset_clean, obs_type, data)
        self.asset_discovery.discover_asset(asset_clean, asset_type="subdomain")

        # Step 2: Change Detection
        change_event = self.change_detector.inspect_and_detect(
            asset=asset_clean,
            property_name=obs_type,
            new_value=data,
            change_type=f"new_{obs_type}"
        )

        # Step 3: Event Emission & Auto-Scheduling New Recon Tasks
        if change_event:
            await self.event_bus.publish("recon.change_detected", {
                "asset": asset_clean,
                "change_type": change_event.change_type,
                "data": data
            })

            # Schedule follow-up recon job
            new_task = self.recon_scheduler.schedule_job(
                target_asset=asset_clean,
                recon_type=f"deep_{obs_type}_recon",
                priority=8
            )
            logger.info(f"[ReconPipeline] Scheduled follow-up recon task for '{asset_clean}'")
            return new_task

        return None
