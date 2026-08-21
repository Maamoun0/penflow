import asyncio
from penflow.agents.injection.dom_xss_agent import DOMXSSAgent
from penflow.capabilities.execution_context import CapabilityExecutionContext
from penflow.infrastructure.browser_pool import BrowserPool
from penflow.knowledge.knowledge_store import KnowledgeStore

async def main():
    print("Initializing BrowserPool...")
    pool = BrowserPool.get_instance()
    await pool.initialize()
    
    agent = DOMXSSAgent()
    ks = KnowledgeStore()
    context = CapabilityExecutionContext(
        asset="https://0a1c00a004c369258006996900480065.web-security-academy.net/",
        knowledge_store=ks,
        observations=[{"data": {"endpoints": [{"url": "https://0a1c00a004c369258006996900480065.web-security-academy.net/"}]}}]
    )
    print("Executing DOMXSSAgent...")
    res = await agent.execute("dom_xss_execution", context)
    
    import json
    print("Result:")
    print(json.dumps(res, indent=2))
    
    await pool.shutdown()

if __name__ == "__main__":
    asyncio.run(main())
