#!/usr/bin/env python3
"""Routes: process management endpoints"""

import json
import logging
import os
import subprocess
import time
import traceback
from datetime import datetime
from typing import Dict, Any, Optional, List

import psutil

from flask import request, jsonify

from core.globals import (
    app, logger,
    decision_engine, error_handler, degradation_manager,
    bugbounty_manager, fileupload_framework,
    tech_detector, rate_limiter, failure_recovery, performance_monitor,
    parameter_optimizer, enhanced_process_manager,
    ctf_manager, ctf_tools, ctf_automator, ctf_coordinator,
    env_manager, cve_intelligence, exploit_generator, vulnerability_correlator,
    http_framework, browser_agent, ai_payload_generator,
    ModernVisualEngine, DEBUG_MODE, COMMAND_TIMEOUT
)
from core.command_executor import (
    execute_command, execute_command_with_recovery, file_manager, cache, telemetry
)
from core.visual_engine import ModernVisualEngine
from core.decision_engine import TargetType, TechnologyStack, TargetProfile, AttackChain
from core.error_handler import ErrorType, RecoveryAction, ErrorContext
from core.process_manager import ProcessManager

# ============================================================================
# PROCESS MANAGEMENT API ENDPOINTS (v5.0 ENHANCEMENT)
# ============================================================================

@app.route("/api/processes/list", methods=["GET"])
def list_processes():
    """List all active processes"""
    try:
        processes = ProcessManager.list_active_processes()

        # Add calculated fields for each process
        for pid, info in processes.items():
            runtime = time.time() - info["start_time"]
            info["runtime_formatted"] = f"{runtime:.1f}s"

            if info["progress"] > 0:
                eta = (runtime / info["progress"]) * (1.0 - info["progress"])
                info["eta_formatted"] = f"{eta:.1f}s"
            else:
                info["eta_formatted"] = "Unknown"

        return jsonify({
            "success": True,
            "active_processes": processes,
            "total_count": len(processes)
        })
    except Exception as e:
        logger.error(f"💥 Error listing processes: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/processes/status/<int:pid>", methods=["GET"])
def get_process_status(pid):
    """Get status of a specific process"""
    try:
        process_info = ProcessManager.get_process_status(pid)

        if process_info:
            # Add calculated fields
            runtime = time.time() - process_info["start_time"]
            process_info["runtime_formatted"] = f"{runtime:.1f}s"

            if process_info["progress"] > 0:
                eta = (runtime / process_info["progress"]) * (1.0 - process_info["progress"])
                process_info["eta_formatted"] = f"{eta:.1f}s"
            else:
                process_info["eta_formatted"] = "Unknown"

            return jsonify({
                "success": True,
                "process": process_info
            })
        else:
            return jsonify({
                "success": False,
                "error": f"Process {pid} not found"
            }), 404

    except Exception as e:
        logger.error(f"💥 Error getting process status: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/processes/terminate/<int:pid>", methods=["POST"])
def terminate_process(pid):
    """Terminate a specific process"""
    try:
        success = ProcessManager.terminate_process(pid)

        if success:
            logger.info(f"🛑 Process {pid} terminated successfully")
            return jsonify({
                "success": True,
                "message": f"Process {pid} terminated successfully"
            })
        else:
            return jsonify({
                "success": False,
                "error": f"Failed to terminate process {pid} or process not found"
            }), 404

    except Exception as e:
        logger.error(f"💥 Error terminating process {pid}: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/processes/pause/<int:pid>", methods=["POST"])
def pause_process(pid):
    """Pause a specific process"""
    try:
        success = ProcessManager.pause_process(pid)

        if success:
            logger.info(f"⏸️ Process {pid} paused successfully")
            return jsonify({
                "success": True,
                "message": f"Process {pid} paused successfully"
            })
        else:
            return jsonify({
                "success": False,
                "error": f"Failed to pause process {pid} or process not found"
            }), 404

    except Exception as e:
        logger.error(f"💥 Error pausing process {pid}: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/processes/resume/<int:pid>", methods=["POST"])
def resume_process(pid):
    """Resume a paused process"""
    try:
        success = ProcessManager.resume_process(pid)

        if success:
            logger.info(f"▶️ Process {pid} resumed successfully")
            return jsonify({
                "success": True,
                "message": f"Process {pid} resumed successfully"
            })
        else:
            return jsonify({
                "success": False,
                "error": f"Failed to resume process {pid} or process not found"
            }), 404

    except Exception as e:
        logger.error(f"💥 Error resuming process {pid}: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/processes/dashboard", methods=["GET"])
def process_dashboard():
    """Get enhanced process dashboard with visual status using ModernVisualEngine"""
    try:
        processes = ProcessManager.list_active_processes()
        current_time = time.time()

        # Create beautiful dashboard using ModernVisualEngine
        dashboard_visual = ModernVisualEngine.create_live_dashboard(processes)

        dashboard = {
            "timestamp": datetime.now().isoformat(),
            "total_processes": len(processes),
            "visual_dashboard": dashboard_visual,
            "processes": [],
            "system_load": {
                "cpu_percent": psutil.cpu_percent(interval=1),
                "memory_percent": psutil.virtual_memory().percent,
                "active_connections": len(psutil.net_connections())
            }
        }

        for pid, info in processes.items():
            runtime = current_time - info["start_time"]
            progress_fraction = info.get("progress", 0)

            # Create beautiful progress bar using ModernVisualEngine
            progress_bar = ModernVisualEngine.render_progress_bar(
                progress_fraction,
                width=25,
                style='cyber',
                eta=info.get("eta", 0)
            )

            process_status = {
                "pid": pid,
                "command": info["command"][:60] + "..." if len(info["command"]) > 60 else info["command"],
                "status": info["status"],
                "runtime": f"{runtime:.1f}s",
                "progress_percent": f"{progress_fraction * 100:.1f}%",
                "progress_bar": progress_bar,
                "eta": f"{info.get('eta', 0):.0f}s" if info.get('eta', 0) > 0 else "Calculating...",
                "bytes_processed": info.get("bytes_processed", 0),
                "last_output": info.get("last_output", "")[:100]
            }
            dashboard["processes"].append(process_status)

        return jsonify(dashboard)

    except Exception as e:
        logger.error(f"💥 Error getting process dashboard: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/visual/vulnerability-card", methods=["POST"])
def create_vulnerability_card():
    """Create a beautiful vulnerability card using ModernVisualEngine"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400

        # Create vulnerability card
        card = ModernVisualEngine.render_vulnerability_card(data)

        return jsonify({
            "success": True,
            "vulnerability_card": card,
            "timestamp": datetime.now().isoformat()
        })

    except Exception as e:
        logger.error(f"💥 Error creating vulnerability card: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/visual/summary-report", methods=["POST"])
def create_summary_report():
    """Create a beautiful summary report using ModernVisualEngine"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400

        # Create summary report
        visual_engine = ModernVisualEngine()
        report = visual_engine.create_summary_report(data)

        return jsonify({
            "success": True,
            "summary_report": report,
            "timestamp": datetime.now().isoformat()
        })

    except Exception as e:
        logger.error(f"💥 Error creating summary report: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/visual/tool-output", methods=["POST"])
def format_tool_output():
    """Format tool output using ModernVisualEngine"""
    try:
        data = request.get_json()
        if not data or 'tool' not in data or 'output' not in data:
            return jsonify({"error": "Tool and output data required"}), 400

        tool = data['tool']
        output = data['output']
        success = data.get('success', True)

        # Format tool output
        formatted_output = ModernVisualEngine.format_tool_output(tool, output, success)

        return jsonify({
            "success": True,
            "formatted_output": formatted_output,
            "timestamp": datetime.now().isoformat()
        })

    except Exception as e:
        logger.error(f"💥 Error formatting tool output: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

