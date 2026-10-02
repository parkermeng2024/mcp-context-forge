# -*- coding: utf-8 -*-
"""Location: ./mcpgateway/admin/events.py
Copyright contributors to the MCP-CONTEXT-FORGE project
SPDX-License-Identifier: Apache-2.0

Admin UI event streaming route: server-sent events from all services.
"""

# Standard
import asyncio
import logging

# Third-Party
from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse
import orjson
from sqlalchemy.orm import Session

# First-Party
from mcpgateway.admin.common import gateway_service, tool_service
from mcpgateway.admin.security import enforce_admin_csrf
from mcpgateway.db import get_db
from mcpgateway.middleware.rbac import get_current_user_with_permissions, require_permission

LOGGER: logging.Logger = logging.getLogger("mcpgateway.admin")

# mcpgateway.admin (__init__) appends this router's routes to admin_router, so the
# prefix, tags, and CSRF dependency must mirror admin_router exactly.
router = APIRouter(
    prefix="/admin",
    tags=["Admin UI"],
    dependencies=[Depends(enforce_admin_csrf)],
)


# Event Streaming via SSE to the Admin UI
@router.get("/events")
@require_permission("admin.events", allow_admin_bypass=False)
async def admin_events(request: Request, _user=Depends(get_current_user_with_permissions), _db: Session = Depends(get_db)):
    """
    Stream admin events from all services via SSE (Server-Sent Events).

    This endpoint establishes a persistent connection to stream real-time updates
    from the gateway service and tool service to the frontend. It aggregates
    multiple event streams into a single asyncio queue for unified delivery.

    Args:
        request (Request): The FastAPI request object, used to detect client disconnection.
        _user (Any): Authenticated user dependency (ensures admin permissions).
        _db: Database session for permission checks.

    Returns:
        StreamingResponse: An async generator yielding SSE-formatted strings
        (media_type="text/event-stream").

    Examples:
        >>> # Test function exists and has correct name
        >>> from mcpgateway.admin import admin_events
        >>> admin_events.__name__
        'admin_events'
        >>> # Test it's a coroutine function
        >>> import inspect
        >>> inspect.iscoroutinefunction(admin_events)
        True
    """
    # Create a shared queue to aggregate events from all services
    event_queue = asyncio.Queue()
    heartbeat_interval = 15.0

    # Define a generic producer that feeds a specific stream into the queue
    async def stream_to_queue(generator, source_name: str):
        """Consume events from an async generator and forward them to a queue.

        This coroutine iterates over an asynchronous generator and enqueues each
        yielded event into a global or external `event_queue`. It gracefully
        handles task cancellation and logs unexpected exceptions.

        Args:
            generator (AsyncGenerator): An asynchronous generator that yields events.
            source_name (str): A human-readable label for the event source, used
                for logging error messages.

        Raises:
            asyncio.CancelledError: If the task is cancelled externally.
            Exception: Any unexpected exception raised while iterating over the
                generator will be caught, logged, and suppressed.

        Doctest:
            >>> import asyncio
            >>> class FakeQueue:
            ...     def __init__(self):
            ...         self.items = []
            ...     async def put(self, item):
            ...         self.items.append(item)
            ...
            >>> async def fake_gen():
            ...     yield 1
            ...     yield 2
            ...     yield 3
            ...
            >>> event_queue = FakeQueue()  # monkey-patch the global name
            >>> async def run_test():
            ...     await stream_to_queue(fake_gen(), "test_source")
            ...     return event_queue.items
            ...
            >>> asyncio.run(run_test())
            [1, 2, 3]

        """
        try:
            async for event in generator:
                await event_queue.put(event)
        except Exception as e:
            LOGGER.error(f"Error in {source_name} event subscription: {e}")

    async def event_generator():
        """
        Asynchronous Server-Sent Events (SSE) generator.

        This coroutine listens to multiple background event streams (e.g., from
        gateway and tool services), funnels their events into a shared queue, and
        yields them to the client in proper SSE format.

        The function:
        - Spawns background tasks to consume events from subscribed services.
        - Monitors the client connection for disconnection.
        - Yields SSE-formatted messages as they arrive.
        - Cleans up subscription tasks on exit.

        The SSE format emitted:
            event: <event_type>
            data: <json-encoded data>

        Yields:
            AsyncGenerator[str, None]: A generator yielding SSE-formatted strings.

        Raises:
            asyncio.CancelledError: If the SSE stream or background tasks are cancelled.
            Exception: Any unexpected exception in the main loop is logged but not re-raised.

        Notes:
            This function expects the following names to exist in the outer scope:
            - `request`: A FastAPI/Starlette Request object.
            - `event_queue`: An asyncio.Queue instance where events are dispatched.
            - `gateway_service` and `tool_service`: Services exposing async subscribe_events().
            - `stream_to_queue`: Coroutine to pipe service streams into the queue.
            - `LOGGER`: Logger instance.

        Example:
            Basic doctest demonstrating SSE formatting from mock data:

            >>> import orjson, asyncio
            >>> class DummyRequest:
            ...     async def is_disconnected(self):
            ...         return False
            >>> async def dummy_gen():
            ...     # Simulate an event queue and minimal environment
            ...     global request, event_queue
            ...     request = DummyRequest()
            ...     event_queue = asyncio.Queue()
            ...     # Minimal stubs to satisfy references
            ...     class DummyService:
            ...         async def subscribe_events(self):
            ...             async def gen():
            ...                 yield {"type": "test", "data": {"a": 1}}
            ...             return gen()
            ...     global gateway_service, tool_service, stream_to_queue, LOGGER
            ...     gateway_service = tool_service = DummyService()
            ...     async def stream_to_queue(gen, tag):
            ...         async for e in gen:
            ...             await event_queue.put(e)
            ...     class DummyLogger:
            ...         def debug(self, *args, **kwargs): pass
            ...         def error(self, *args, **kwargs): pass
            ...     LOGGER = DummyLogger()
            ...
            ...     agen = event_generator()
            ...     # Startup requires allowing tasks to enqueue
            ...     async def get_one():
            ...         async for msg in agen:
            ...             return msg
            ...     return (await get_one()).startswith("event: test")
            >>> asyncio.run(dummy_gen())
            True
        """
        # Create background tasks for each service subscription
        # This allows them to run concurrently
        tasks = [asyncio.create_task(stream_to_queue(gateway_service.subscribe_events(), "gateway")), asyncio.create_task(stream_to_queue(tool_service.subscribe_events(), "tool"))]

        try:
            while True:
                # Check for client disconnection
                if await request.is_disconnected():
                    LOGGER.debug("SSE Client disconnected")
                    break

                # Wait for the next event from EITHER service
                # We use asyncio.wait_for to allow checking request.is_disconnected periodically
                # or simply rely on queue.get() which is efficient.
                try:
                    # Wait for an event or send a keepalive to avoid idle timeouts
                    event = await asyncio.wait_for(event_queue.get(), timeout=heartbeat_interval)

                    # SSE format
                    event_type = event.get("type", "message")
                    event_data = orjson.dumps(event.get("data", {})).decode()

                    yield f"event: {event_type}\ndata: {event_data}\n\n"

                    # Mark task as done in queue (good practice)
                    event_queue.task_done()
                except asyncio.TimeoutError:
                    yield ": keepalive\n\n"

                except asyncio.CancelledError:
                    LOGGER.debug("SSE Event generator task cancelled")
                    raise

        except asyncio.CancelledError:
            LOGGER.debug("SSE Stream cancelled")
            raise
        except Exception as e:
            LOGGER.error(f"SSE Stream error: {e}")
        finally:
            # Cleanup: Cancel all background subscription tasks
            # This is crucial to close Redis connections/listeners in the EventService
            for task in tasks:
                task.cancel()

            # Wait for tasks to clean up
            await asyncio.gather(*tasks, return_exceptions=True)
            LOGGER.debug("Background event subscription tasks cleaned up")

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
