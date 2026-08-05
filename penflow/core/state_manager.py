import time
import uuid
from pathlib import Path
from typing import Dict, Any, Tuple, Optional

from penflow.config import Config
from penflow.utils.logger import get_logger
from penflow.utils.file_utils import ensure_dir, safe_read_json, safe_write_json, rotate_files

logger = get_logger("penflow.core.state_manager")

class StateManager:
    def __init__(self, target_name: str):
        self.target_name = target_name
        self.config = Config.load()
        
        base_state_dir = Path(self.config.get("state.directory", "state"))
        self.state_dir = ensure_dir(base_state_dir / target_name)
        
        self.checkpoint_file = self.state_dir / "checkpoint.json"
        self.session_file = self.state_dir / "session.json"
        
        self.session_id = None
        self.last_checkpoint_time = 0.0
        self.auto_checkpoint_interval = self.config.get("state.auto_checkpoint_interval_seconds", 30)
        self.max_checkpoints = self.config.get("state.max_checkpoints", 10)

    def create_session(self, config_overrides: dict = None) -> str:
        """Create a new scan session."""
        self.session_id = str(uuid.uuid4())
        session_data = {
            "session_id": self.session_id,
            "target": self.target_name,
            "start_time": time.time(),
            "config_overrides": config_overrides or {},
            "status": "initialized"
        }
        safe_write_json(self.session_file, session_data)
        logger.info(f"Created new session {self.session_id} for {self.target_name}")
        return self.session_id

    def update_session(self, status: str, additional_data: dict = None) -> None:
        """Update session status."""
        data = safe_read_json(self.session_file)
        data["status"] = status
        data["last_updated"] = time.time()
        
        if additional_data:
            data.update(additional_data)
            
        safe_write_json(self.session_file, data)

    def save_checkpoint(self, phase: str, progress: dict, force: bool = False) -> None:
        """Save scan progress checkpoint."""
        now = time.time()
        
        if not force and (now - self.last_checkpoint_time) < self.auto_checkpoint_interval:
            return
            
        checkpoint_data = {
            "session_id": self.session_id,
            "target": self.target_name,
            "timestamp": now,
            "phase": phase,
            "progress": progress
        }
        
        # Save to main checkpoint file
        safe_write_json(self.checkpoint_file, checkpoint_data)
        self.last_checkpoint_time = now
        
        # Keep a backup of this specific phase
        phase_file = self.state_dir / f"checkpoint_{phase}.json"
        safe_write_json(phase_file, checkpoint_data)
        
        # Rotate old backup files
        rotate_files(self.state_dir, self.max_checkpoints)

    def load_checkpoint(self) -> Optional[Dict[str, Any]]:
        """Load the latest checkpoint."""
        if not self.checkpoint_file.exists():
            return None
        return safe_read_json(self.checkpoint_file)

    def can_resume(self) -> bool:
        """Check if a valid resume point exists."""
        data = self.load_checkpoint()
        if not data:
            return False
            
        # Optional: check if session is marked as 'completed'
        session = safe_read_json(self.session_file)
        if session.get("status") in ("completed", "failed_fatally"):
            return False
            
        return True

    def get_resume_point(self) -> Tuple[str, dict]:
        """Get the phase and progress to resume from."""
        data = self.load_checkpoint()
        if not data:
            return "recon", {}
            
        self.session_id = data.get("session_id")
        return data.get("phase", "recon"), data.get("progress", {})
        
    def clear_state(self) -> None:
        """Clear state files for a fresh start."""
        if self.checkpoint_file.exists():
            self.checkpoint_file.unlink()
        if self.session_file.exists():
            self.session_file.unlink()
