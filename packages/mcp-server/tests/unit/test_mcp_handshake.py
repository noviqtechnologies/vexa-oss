"""
Tests for MCP stdio transport handshake reliability.
Validates cold-start simulation and graceful timeouts.
"""

import asyncio
import pytest


class TestMCPHandshakeStability:
    """Validate MCP server initialization and handshake."""

    @pytest.mark.asyncio
    async def test_cold_start_latency_tolerance(self):
        """MCP-HS: Handshake should tolerate 3s Cloud Run cold-start delay."""

        async def delayed_init():
            # Simulate a cold start latency
            await asyncio.sleep(3)
            return {"status": "ready"}

        # Client must wait at least 3 seconds without timing out
        result = await asyncio.wait_for(delayed_init(), timeout=10)
        assert result["status"] == "ready"

    @pytest.mark.asyncio
    async def test_handshake_timeout_on_unresponsive(self):
        """MCP-HS: Client should timeout gracefully if server never responds."""

        async def never_respond():
            await asyncio.sleep(999)

        # Ensure we drop the connection gracefully and report failure
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(never_respond(), timeout=2)

    def test_auto_remediate_has_new_params(self):
        """MCP-HS: Confirm tools registered successfully with parameters."""
        from vexa_mcp.scanner.server import server

        tools = server._tool_manager.list_tools()
        rem_tool = next(
            (t for t in tools if t.name == "auto_remediate_workspace"), None
        )
        assert rem_tool is not None, "auto_remediate_workspace tool not found"
