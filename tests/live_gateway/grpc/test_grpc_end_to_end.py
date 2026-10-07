# -*- coding: utf-8 -*-
"""Location: ./tests/live_gateway/grpc/test_grpc_end_to_end.py
Copyright contributors to the MCP-CONTEXT-FORGE project
SPDX-License-Identifier: Apache-2.0

Black-box gRPC end-to-end verification against a running gateway.

Prerequisites:
    export MCPGATEWAY_BEARER_TOKEN=$(python -m mcpgateway.utils.create_jwt_token \
        --username admin@example.com --exp 60 --secret "$JWT_SECRET_KEY")
    export MCPGATEWAY_TEST_URL=http://127.0.0.1:8001
    MCPGATEWAY_GRPC_ENABLED=true on the gateway

The module starts a reflected echo gRPC server, then drives the gateway:
register -> reflect -> list methods -> create a gRPC-backed tool -> invoke.
"""

# Standard
import os
import pathlib
import socket
import subprocess
import sys
import time
import uuid

# Third-Party
import httpx
import pytest

HERE = pathlib.Path(__file__).resolve().parent
BASE_URL = os.environ.get("MCPGATEWAY_TEST_URL", "http://127.0.0.1:8001")
TOKEN = os.environ.get("MCPGATEWAY_BEARER_TOKEN")

pytestmark = pytest.mark.skipif(not TOKEN, reason="MCPGATEWAY_BEARER_TOKEN is not set")


def _free_port() -> int:
    """Return a free TCP port on the loopback interface."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _wait_for_port(port: int, timeout: float = 20.0) -> None:
    """Block until ``port`` accepts connections."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.2)
    raise TimeoutError(f"nothing listening on 127.0.0.1:{port}")


@pytest.fixture()
def echo_server():
    """Run the reflected echo gRPC server for the duration of a test."""
    port = _free_port()
    proc = subprocess.Popen(
        [sys.executable, str(HERE / "echo_server.py"), str(port)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    try:
        _wait_for_port(port)
        yield port
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()


def test_grpc_service_registry_reflect_and_tool_wiring(echo_server):
    """The full admin flow works when MCPGATEWAY_GRPC_ENABLED is true."""
    headers = {"Authorization": f"Bearer {TOKEN}"}
    name = f"e2e-grpc-{uuid.uuid4().hex[:8]}"
    service_id = None
    tool_id = None

    try:
        with httpx.Client(base_url=BASE_URL, headers=headers, timeout=60.0) as client:
            created = client.post(
                "/admin/grpc",
                json={"name": name, "target": f"127.0.0.1:{echo_server}", "reflection_enabled": True},
            )
            assert created.status_code == 201, created.text
            service_id = created.json()["id"]

            listed = client.get("/admin/grpc")
            assert listed.status_code == 200, listed.text
            assert any(item["name"] == name for item in listed.json()["data"]), "panel list must include the new service"

            fetched = client.get(f"/admin/grpc/{service_id}")
            assert fetched.status_code == 200, fetched.text

            reflected = client.post(f"/admin/grpc/{service_id}/reflect")
            assert reflected.status_code == 200, reflected.text

            methods = client.get(f"/admin/grpc/{service_id}/methods")
            assert methods.status_code == 200, methods.text
            assert "Echo" in methods.text

            tool = client.post(
                "/admin/tools",
                json={
                    "name": f"{name}-echo",
                    "integration_type": "gRPC",
                    "request_type": "GET",
                    "grpc_service_id": service_id,
                    "input_schema": {"type": "object", "properties": {"message": {"type": "string"}}},
                },
            )
            assert tool.status_code in (200, 201), tool.text
            tool_id = tool.json().get("id")

            stored = client.get(f"/admin/tools/{tool_id}")
            assert stored.status_code == 200, stored.text
            assert stored.json().get("grpc_service_id") == service_id
    finally:
        with httpx.Client(base_url=BASE_URL, headers=headers, timeout=60.0) as client:
            if tool_id:
                client.post(f"/admin/tools/{tool_id}/delete")
            if service_id:
                client.post(f"/admin/grpc/{service_id}/delete")


def test_invoke_method_reaches_the_echo_server(echo_server):
    """GrpcService.invoke_method calls the live server through reflected descriptors."""
    pytest.importorskip("grpc")

    # First-Party
    from mcpgateway.db import SessionLocal  # noqa: E402
    from mcpgateway.services.grpc_service import GrpcService  # noqa: E402
    from mcpgateway.schemas import GrpcServiceCreate  # noqa: E402

    import asyncio  # noqa: E402

    async def _run():
        manager = GrpcService()
        with SessionLocal() as db:
            service = await manager.register_service(
                db,
                GrpcServiceCreate(name=f"invoke-{uuid.uuid4().hex[:8]}", target=f"127.0.0.1:{echo_server}", reflection_enabled=True),
                "e2e@example.com",
                {},
            )
            try:
                reply = await manager.invoke_method(db, service.id, "echogrpc.EchoService.Echo", {"message": "hello"}, timeout=15)
                assert reply == {"message": "hello"}
            finally:
                await manager.delete_service(db, service.id)

    asyncio.run(_run())
