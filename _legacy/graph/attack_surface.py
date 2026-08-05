import networkx as nx
from typing import Dict, List, Any, Optional
from pathlib import Path
import json

from penflow.utils.logger import get_logger
from penflow.utils.file_utils import safe_write_json, safe_read_json, ensure_dir

logger = get_logger("penflow.graph.attack_surface")

class AttackSurfaceGraph:
    def __init__(self, target_name: str):
        self.target_name = target_name
        self.graph = nx.DiGraph()

    def add_domain(self, name: str, **attrs) -> str:
        node_id = f"domain:{name}"
        self.graph.add_node(node_id, type="DOMAIN", name=name, **attrs)
        return node_id

    def add_subdomain(self, domain_id: str, name: str, ip: str = None, alive: bool = True, source: str = "") -> str:
        node_id = f"subdomain:{name}"
        self.graph.add_node(node_id, type="SUBDOMAIN", name=name, ip=ip, alive=alive, source=source)
        self.graph.add_edge(domain_id, node_id, type="HOSTS")
        return node_id

    def add_endpoint(self, subdomain_id: str, url: str, method: str = "GET", 
                     status: int = 0, content_type: str = "", auth_required: bool = False, 
                     classification: str = "page") -> str:
        node_id = f"endpoint:{method}:{url}"
        self.graph.add_node(
            node_id, 
            type="ENDPOINT", 
            url=url, 
            method=method, 
            status=status,
            content_type=content_type,
            auth_required=auth_required,
            classification=classification
        )
        if subdomain_id:
            self.graph.add_edge(subdomain_id, node_id, type="SERVES")
        return node_id

    def add_parameter(self, endpoint_id: str, name: str, param_type: str = "string", location: str = "query") -> str:
        # Avoid extremely long node IDs if endpoint is long
        node_id = f"param:{endpoint_id}:{name}"
        self.graph.add_node(node_id, type="PARAMETER", name=name, param_type=param_type, location=location)
        self.graph.add_edge(endpoint_id, node_id, type="ACCEPTS")
        return node_id

    def add_technology(self, source_id: str, name: str, version: str = "", category: str = "framework") -> str:
        node_id = f"tech:{name}:{version}"
        if not self.graph.has_node(node_id):
            self.graph.add_node(node_id, type="TECHNOLOGY", name=name, version=version, category=category)
            
        edge_type = "RUNS" if "subdomain" in source_id else "USES"
        self.graph.add_edge(source_id, node_id, type=edge_type)
        return node_id

    def query_nodes(self, node_type: str, **filters) -> List[Dict[str, Any]]:
        results = []
        for n, data in self.graph.nodes(data=True):
            if data.get("type") == node_type:
                match = True
                for k, v in filters.items():
                    if data.get(k) != v:
                        match = False
                        break
                if match:
                    results.append({"id": n, **data})
        return results

    def get_endpoints_by_classification(self, classification: str) -> List[Dict[str, Any]]:
        return self.query_nodes("ENDPOINT", classification=classification)

    def get_technologies_for_subdomain(self, subdomain_id: str) -> List[str]:
        techs = []
        for _, neighbor, data in self.graph.out_edges(subdomain_id, data=True):
            if data.get("type") == "RUNS" and self.graph.nodes[neighbor].get("type") == "TECHNOLOGY":
                techs.append(self.graph.nodes[neighbor].get("name"))
        return techs

    def save(self, filepath: Path) -> None:
        """Serialize graph to Node-Link JSON format."""
        data = nx.node_link_data(self.graph)
        safe_write_json(filepath, data)
        logger.info(f"Graph saved to {filepath}")

    @classmethod
    def load(cls, target_name: str, filepath: Path) -> 'AttackSurfaceGraph':
        """Load graph from JSON."""
        instance = cls(target_name)
        data = safe_read_json(filepath)
        if data:
            instance.graph = nx.node_link_graph(data)
            logger.info(f"Graph loaded from {filepath}")
        return instance

    def get_stats(self) -> Dict[str, int]:
        stats = {
            "domains": len(self.query_nodes("DOMAIN")),
            "subdomains": len(self.query_nodes("SUBDOMAIN")),
            "endpoints": len(self.query_nodes("ENDPOINT")),
            "parameters": len(self.query_nodes("PARAMETER")),
            "technologies": len(self.query_nodes("TECHNOLOGY"))
        }
        return stats
