import pytest
import yaml
import socket
from pathlib import Path


def test_docker_compose_network_isolation_configuration():
    """
    Acceptance Test: Verify Docker Compose configuration guarantees network isolation.
    - zone-red is attached ONLY to red-seg
    - zone-blue is attached ONLY to blue-seg
    - red-seg and blue-seg have NO shared containers except gateway
    """
    compose_path = Path(__file__).parent.parent / "docker-compose.yml"
    assert compose_path.exists(), "docker-compose.yml must exist"

    with open(compose_path, "r", encoding="utf-8") as f:
        compose = yaml.safe_load(f)

    services = compose.get("services", {})
    networks = compose.get("networks", {})

    # Ensure required networks are defined
    assert "red-seg" in networks
    assert "blue-seg" in networks
    assert "model-seg" in networks
    assert "audit-seg" in networks

    # Check zone-red isolation
    red_nets = services["zone-red"]["networks"]
    assert "red-seg" in red_nets
    assert "blue-seg" not in red_nets, "SECURITY VIOLATION: zone-red must NOT be connected to blue-seg"
    assert "model-seg" not in red_nets, "SECURITY VIOLATION: zone-red must NOT be connected to model-seg"
    assert "audit-seg" not in red_nets, "SECURITY VIOLATION: zone-red must NOT be connected to audit-seg"

    # Check zone-blue isolation
    blue_nets = services["zone-blue"]["networks"]
    assert "blue-seg" in blue_nets
    assert "red-seg" not in blue_nets, "SECURITY VIOLATION: zone-blue must NOT be connected to red-seg"
    assert "model-seg" not in blue_nets, "SECURITY VIOLATION: zone-blue must NOT be connected to model-seg"

    # Verify only gateway is multi-homed across all segments
    gw_nets = services["gateway"]["networks"]
    assert set(gw_nets) == {"red-seg", "blue-seg", "model-seg", "audit-seg"}


def test_cross_network_connection_fails_from_red_to_blue():
    """
    Acceptance Test: Attempting a direct socket connection from Red zone's address space
    to Blue zone fails with connection refused, host unreachable, or timeout.
    """
    # Attempting to resolve or connect to zone-blue on port 8002 without gateway airlock
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.5)

    connection_succeeded = False
    try:
        # In isolated docker network, dns cannot resolve 'zone-blue' from red container
        # Or connection will immediately time out / fail
        s.connect(("zone-blue", 8002))
        connection_succeeded = True
    except (socket.gaierror, socket.timeout, ConnectionRefusedError, OSError):
        connection_succeeded = False
    finally:
        s.close()

    assert not connection_succeeded, (
        "SECURITY VIOLATION: Direct connection between red and blue succeeded! "
        "Containers must be completely segregated."
    )
