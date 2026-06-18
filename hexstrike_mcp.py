#!/usr/bin/env python3
"""
HexStrike AI MCP Client - Enhanced AI Agent Communication Interface
Entry point: sets up MCP server with all tool registrations.
"""

import sys
import os
import argparse
import logging

from mcp.server.fastmcp import FastMCP

from mcp_tools.core import (
    HexStrikeClient, HexStrikeColors, ColoredFormatter,
    DEFAULT_HEXSTRIKE_SERVER, DEFAULT_REQUEST_TIMEOUT
)
from mcp_tools.network import register_network_tools
from mcp_tools.cloud import register_cloud_tools
from mcp_tools.web import register_web_tools
from mcp_tools.binary import register_binary_tools
from mcp_tools.ctf import register_ctf_tools
from mcp_tools.system import register_system_tools
from mcp_tools.intelligence import register_intelligence_tools

# Apply colored formatter
for handler in logging.getLogger().handlers:
    handler.setFormatter(ColoredFormatter(
        "[🔥 HexStrike MCP] %(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    ))

logger = logging.getLogger(__name__)


def setup_mcp_server(hexstrike_client: HexStrikeClient) -> FastMCP:
    """Set up the MCP server with all enhanced tool functions."""
    mcp = FastMCP("hexstrike-ai-tools")

    register_network_tools(mcp, hexstrike_client)
    register_cloud_tools(mcp, hexstrike_client)
    register_system_tools(mcp, hexstrike_client)
    register_web_tools(mcp, hexstrike_client)
    register_binary_tools(mcp, hexstrike_client)
    register_ctf_tools(mcp, hexstrike_client)
    register_intelligence_tools(mcp, hexstrike_client)

    return mcp


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Run the HexStrike AI MCP Client")
    parser.add_argument("--server", type=str, default=DEFAULT_HEXSTRIKE_SERVER,
                      help=f"HexStrike AI API server URL (default: {DEFAULT_HEXSTRIKE_SERVER})")
    parser.add_argument("--timeout", type=int, default=DEFAULT_REQUEST_TIMEOUT,
                      help=f"Request timeout in seconds (default: {DEFAULT_REQUEST_TIMEOUT})")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument("--quiet", "-q", action="store_true", help="Silence log output")
    return parser.parse_args()

def main():
    """Main entry point for the MCP server."""
    args = parse_args()

    # Configure logging based on flags
    if args.quiet:
        logging.getLogger().setLevel(logging.CRITICAL)
    elif args.debug:
        logger.setLevel(logging.DEBUG)
        logger.debug("🔍 Debug logging enabled")

    # MCP compatibility: No banner output to avoid JSON parsing issues
    logger.info(f"🚀 Starting HexStrike AI MCP Client v6.0")
    logger.info(f"🔗 Connecting to: {args.server}")

    try:
        # Initialize the HexStrike AI client
        hexstrike_client = HexStrikeClient(args.server, args.timeout)

        # Check server health and log the result
        health = hexstrike_client.check_health()
        if "error" in health:
            logger.warning(f"⚠️  Unable to connect to HexStrike AI API server at {args.server}: {health['error']}")
            logger.warning("🚀 MCP server will start, but tool execution may fail")
        else:
            logger.info(f"🎯 Successfully connected to HexStrike AI API server at {args.server}")
            logger.info(f"🏥 Server health status: {health['status']}")
            logger.info(f"📊 Version: {health.get('version', 'unknown')}")
            if not health.get("all_essential_tools_available", False):
                logger.warning("⚠️  Not all essential tools are available on the server")
                missing_tools = [tool for tool, available in health.get("tools_status", {}).items() if not available]
                if missing_tools:
                    logger.warning(f"❌ Missing tools: {', '.join(missing_tools[:10])}")

        # Set up and run the MCP server
        mcp = setup_mcp_server(hexstrike_client)
        logger.info("🚀 Starting HexStrike AI MCP server")
        logger.info("🤖 Ready to serve AI agents with enhanced cybersecurity capabilities")
        mcp.run()
    except Exception as e:
        logger.error(f"💥 Error starting MCP server: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())
        sys.exit(1)

if __name__ == "__main__":
    main()
