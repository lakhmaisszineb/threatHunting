from threat_hunting.agents.hypothesis import hypothesis_agent
from threat_hunting.agents.ioc_cti import ioc_cti_agent
from threat_hunting.agents.mitre import mitre_mapping_agent
from threat_hunting.agents.network_analysis import network_analysis_agent
from threat_hunting.agents.supervisor import supervisor_node
from threat_hunting.core.graph import run_investigation


NORMALIZED_DATA = {
    "summary": {"total_connections": 2, "unique_src_ips": 1, "unique_dst_ips": 1},
    "zeek": {
        "conn": [
            {
                "id.orig_h": "10.0.0.5",
                "id.resp_h": "192.0.2.10",
                "id.resp_p": port,
                "conn_state": "REJ",
            }
            for port in (22, 80)
        ],
        "dns": [
            {"id.orig_h": "10.0.0.5", "query": "example.test", "answers": ["192.0.2.10"]}
        ],
        "weird": [],
    },
}

ALERTS = [
    {
        "rule": "possible_port_scan",
        "src_ip": "10.0.0.5",
        "severity": "medium",
        "description": "Plusieurs ports contactés",
    }
]


def test_agents_produce_structured_results():
    state = {"normalized_data": NORMALIZED_DATA, "alerts": ALERTS}

    hypotheses = hypothesis_agent(state)
    state.update(hypotheses)
    network = network_analysis_agent(state)
    state.update(network)
    iocs = ioc_cti_agent(state)
    state.update(iocs)
    mappings = mitre_mapping_agent(state)
    state.update(mappings)

    assert len(state["hypotheses"]) == 1
    assert state["network_analysis"]["analyses"][0]["evidence"]["connection_count"] == 2
    assert {item["value"] for item in state["ioc_findings"]} >= {"10.0.0.5", "192.0.2.10", "example.test"}
    assert state["mitre_mappings"][0]["technique_id"] == "T1595"


def test_supervisor_does_not_claim_confirmed_compromise():
    state = {
        "normalized_data": NORMALIZED_DATA,
        "alerts": ALERTS,
        "hypotheses": hypothesis_agent({"alerts": ALERTS})["hypotheses"],
        "network_analysis": network_analysis_agent(
            {"normalized_data": NORMALIZED_DATA, "alerts": ALERTS}
        )["network_analysis"],
        "ioc_findings": [],
        "mitre_mappings": [],
    }

    report = supervisor_node(state)["final_report"]

    assert report["confidence"] == "medium"
    assert "ne peut pas être confirmée" in report["conclusion"]


def test_graph_runs_all_agents():
    result = run_investigation(NORMALIZED_DATA, ALERTS)

    assert result["current_step"] == "supervisor_completed"
    assert result["final_report"]["meta"]["type"] == "investigation_report"
    assert any(message.startswith("[hypothesis_agent]") for message in result["messages"])
    assert any(message.startswith("[supervisor]") for message in result["messages"])
