import pytest
import asyncio
from penflow.core.capability_registry import CapabilityRegistry
from penflow.core.scheduler import DAGScheduler
from penflow.core.worker_pool import WorkerPool
from penflow.core.lifecycle import AgentLifecycleState, AgentStateMachine
from penflow.domain.models import Task, Goal, Plan

def test_capability_registry():
    registry = CapabilityRegistry()
    registry.register_capability("agent_idor_01", "id_access_analysis", cost_factor=1.0, version="1.0.0")
    registry.register_capability("agent_idor_02_cheap", "id_access_analysis", cost_factor=0.2, version="2.0.0")

    best_agent = registry.find_best_agent("id_access_analysis")
    assert best_agent == "agent_idor_02_cheap"

def test_agent_lifecycle_state_machine():
    machine = AgentStateMachine(agent_id="test_worker")
    assert machine.state == AgentLifecycleState.INITIALIZED
    
    machine.transition_to(AgentLifecycleState.REGISTERED)
    assert machine.state == AgentLifecycleState.REGISTERED
    
    machine.transition_to(AgentLifecycleState.RUNNING)
    assert machine.state == AgentLifecycleState.RUNNING
    
    machine.transition_to(AgentLifecycleState.CLEANUP)
    assert machine.state == AgentLifecycleState.CLEANUP

def test_dag_scheduler_topological_resolution():
    scheduler = DAGScheduler()
    t1 = Task(id="t1", agent_assigned="Worker1", status="COMPLETED")
    t2 = Task(id="t2", agent_assigned="Worker2", dag_dependencies=["t1"], status="PENDING")
    
    plan = Plan(goal_id="g1", tasks=[t1, t2])
    runnable = scheduler.get_runnable_tasks(plan)
    assert len(runnable) == 1
    assert runnable[0].id == "t2"

@pytest.mark.asyncio
async def test_worker_pool_concurrency():
    pool = WorkerPool(max_workers=2)
    assert len(pool.workers) == 2
