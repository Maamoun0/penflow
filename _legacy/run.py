import asyncio
import sys
from pathlib import Path

# Add project root to sys.path so 'penflow' imports work
project_root = Path(__file__).parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from penflow.core.orchestrator import Orchestrator
from penflow.utils.logger import get_logger

logger = get_logger("penflow.cli")

async def main():
    if len(sys.argv) < 2:
        print("Usage: python run.py <target_domain>")
        print("Example: python run.py example.com")
        sys.exit(1)
        
    target = sys.argv[1]
    
    # Initialize the orchestrator
    orchestrator = Orchestrator(target)
    
    # Run the full pipeline
    try:
        await orchestrator.run()
    except KeyboardInterrupt:
        logger.info("Scan aborted by user.")
        sys.exit(0)

if __name__ == "__main__":
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(main())
