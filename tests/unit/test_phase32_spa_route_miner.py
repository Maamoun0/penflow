"""
Phase 32 Unit Tests — SPA Dynamic Route Miner.
Verifies parsing of Next.js, React Router, Vue Router, and Angular route structures.
"""
import pytest
from penflow.recon.spa_route_miner import SPARouteMiner


def test_spa_route_miner_extraction():
    miner = SPARouteMiner()

    sample_bundle = '''
        const routes = [
            { path: "/admin/dashboard", element: React.createElement(AdminDashboard) },
            { path: "/users/:id/profile", component: UserProfile },
            { path: '/settings/billing', component: BillingView }
        ];

        function fetchUserData(id) {
            return fetch("/api/v1/users/" + id + "/details");
        }
        const apiPath = "/api/v2/auth/token";
    '''

    res = miner.extract_routes_from_js(sample_bundle)
    assert len(res["routes"]) >= 3
    assert "/admin/dashboard" in res["routes"]
    assert "/users/:id/profile" in res["routes"]
    assert "/settings/billing" in res["routes"]
    assert len(res["api_endpoints"]) >= 2
    assert "/api/v2/auth/token" in res["api_endpoints"]
