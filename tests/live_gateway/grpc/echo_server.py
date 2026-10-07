# -*- coding: utf-8 -*-
"""Location: ./tests/live_gateway/grpc/echo_server.py
Copyright contributors to the MCP-CONTEXT-FORGE project
SPDX-License-Identifier: Apache-2.0

Minimal reflected gRPC echo server used by the gRPC end-to-end test.

Run it standalone::

    python tests/live_gateway/grpc/echo_server.py 50051
"""

# Standard
import argparse
import concurrent.futures
import pathlib
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent


def generate_stubs() -> None:
    """Generate ``echo_pb2`` modules next to ``echo.proto`` when they are missing."""
    if (HERE / "echo_pb2.py").exists() and (HERE / "echo_pb2_grpc.py").exists():
        return
    subprocess.check_call(
        [
            sys.executable,
            "-m",
            "grpc_tools.protoc",
            f"-I{HERE}",
            f"--python_out={HERE}",
            f"--grpc_python_out={HERE}",
            "echo.proto",
        ],
        cwd=HERE,
    )


def serve(host: str = "127.0.0.1", port: int = 50051) -> None:
    """Serve ``echogrpc.EchoService`` with server reflection enabled."""
    generate_stubs()
    if str(HERE) not in sys.path:
        sys.path.insert(0, str(HERE))

    # Third-Party
    import grpc
    from grpc_reflection.v1alpha import reflection

    # Local
    import echo_pb2
    import echo_pb2_grpc

    class EchoService(echo_pb2_grpc.EchoServiceServicer):
        """Echo one string back to the caller."""

        def Echo(self, request, context):  # noqa: N802 - gRPC naming
            """Return the request message unchanged."""
            return echo_pb2.EchoReply(message=request.message)

    server = grpc.server(concurrent.futures.ThreadPoolExecutor(max_workers=4))
    echo_pb2_grpc.add_EchoServiceServicer_to_server(EchoService(), server)
    reflection.enable_server_reflection(
        (
            echo_pb2.DESCRIPTOR.services_by_name["EchoService"].full_name,
            reflection.SERVICE_NAME,
        ),
        server,
    )
    server.add_insecure_port(f"{host}:{port}")
    server.start()
    print(f"echo gRPC server listening on {host}:{port}", flush=True)
    server.wait_for_termination()


def main() -> None:
    """Parse arguments and serve."""
    parser = argparse.ArgumentParser(description="Reflected gRPC echo server")
    parser.add_argument("port", type=int, nargs="?", default=50051)
    parser.add_argument("--host", default="127.0.0.1")
    args = parser.parse_args()
    serve(args.host, args.port)


if __name__ == "__main__":
    main()
