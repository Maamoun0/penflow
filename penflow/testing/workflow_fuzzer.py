"""
Stateful Business Logic Workflow Engine for PenFlow.

Maps multi-step business transaction sequences (e.g., Cart -> Apply Coupon -> Checkout -> Process Payment)
and performs order-skipping, parameter tampering, price manipulation, and step-bypass fuzzing.
"""
from typing import List, Dict, Any, Optional
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.testing.workflow_fuzzer")


class BusinessStep:
    """Represents a single step in a multi-step business transaction flow."""
    def __init__(self, step_number: int, name: str, endpoint_url: str, method: str,
                 required_state: Dict[str, Any] = None, payload_template: Dict[str, Any] = None):
        self.step_number = step_number
        self.name = name
        self.endpoint_url = endpoint_url
        self.method = method
        self.required_state = required_state or {}
        self.payload_template = payload_template or {}


class WorkflowFuzzer:
    """
    Stateful Business Logic Workflow Engine.
    Executes transaction sequence mutations to uncover step-bypass and business logic flaws.
    """

    def create_checkout_workflow(self, origin: str) -> List[BusinessStep]:
        base = origin.rstrip("/")
        return [
            BusinessStep(1, "Add to Cart", f"{base}/api/v1/cart/add", "POST", payload_template={"item_id": 101, "quantity": 1, "price": 99.99}),
            BusinessStep(2, "Apply Discount Code", f"{base}/api/v1/cart/apply-coupon", "POST", payload_template={"coupon": "SAVE50"}),
            BusinessStep(3, "Shipping Information", f"{base}/api/v1/checkout/shipping", "POST", payload_template={"address": "123 Test St"}),
            BusinessStep(4, "Process Payment & Finalize", f"{base}/api/v1/checkout/pay", "POST", payload_template={"cart_total": 49.99, "payment_token": "tok_visa"})
        ]

    def generate_step_bypass_mutations(self, workflow: List[BusinessStep]) -> List[Dict[str, Any]]:
        """Generates order-skipping and parameter manipulation mutations across workflow steps."""
        mutations: List[Dict[str, Any]] = []

        if len(workflow) >= 3:
            # Skip intermediate steps (Step 1 -> Step 4 directly)
            mutations.append({
                "name": "StepBypass_DirectCheckout",
                "type": "step_skip",
                "skipped_steps": [2, 3],
                "target_step": workflow[-1],
                "description": "Attempting final payment step directly without completing shipping and coupon validation"
            })

        # Price alteration mutation on final step
        final_step = workflow[-1]
        tamp_payload = dict(final_step.payload_template)
        if "cart_total" in tamp_payload:
            tamp_payload["cart_total"] = 0.00

        mutations.append({
            "name": "PriceTamper_ZeroPayment",
            "type": "parameter_tamper",
            "target_step": final_step,
            "tampered_payload": tamp_payload,
            "description": "Attempting final checkout with price overridden to 0.00"
        })

        logger.info(f"[WorkflowFuzzer] Generated {len(mutations)} workflow mutations for transaction flow.")
        return mutations
