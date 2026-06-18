#!/usr/bin/env python3
"""
Central globals module: Flask app, config, logging, and all singleton instances.
All other modules import from here to access shared state.
"""

import argparse
import json
import logging
import os
import subprocess
import sys
import traceback
import threading
import time
import hashlib
import pickle
import base64
import queue
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
from collections import OrderedDict
import shutil
import venv
import zipfile
from pathlib import Path
from flask import Flask, request, jsonify
import psutil
import signal
import requests
import re
import socket
import urllib.parse
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Set, Tuple
import asyncio
import aiohttp
from urllib.parse import urljoin, urlparse, parse_qs
try:
    from bs4 import BeautifulSoup
except ImportError:
    BeautifulSoup = None
try:
    import selenium
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.common.exceptions import TimeoutException, WebDriverException
except ImportError:
    selenium = None
try:
    import mitmproxy
    from mitmproxy import http as mitmhttp
    from mitmproxy.tools.dump import DumpMaster
    from mitmproxy.options import Options as MitmOptions
except ImportError:
    mitmproxy = None

# ============================================================================
# LOGGING CONFIGURATION (MUST BE FIRST)
# ============================================================================

# Configure logging with fallback for permission issues
try:
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler('hexstrike.log')
        ]
    )
except PermissionError:
    # Fallback to console-only logging if file creation fails
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout)
        ]
    )
logger = logging.getLogger(__name__)

# Flask app configuration
app = Flask(__name__)
app.config['JSON_SORT_KEYS'] = False

# API Configuration
API_PORT = int(os.environ.get('HEXSTRIKE_PORT', 8888))
API_HOST = os.environ.get('HEXSTRIKE_HOST', '127.0.0.1')

# Additional config
DEBUG_MODE = os.environ.get("DEBUG_MODE", "0").lower() in ("1", "true", "yes", "y")
COMMAND_TIMEOUT = int(os.environ.get('COMMAND_TIMEOUT', 300))
CACHE_SIZE = 1000
CACHE_TTL = 3600

# ============================================================================
# IMPORT CORE CLASSES
# ============================================================================

from core.visual_engine import ModernVisualEngine
from core.decision_engine import (
    IntelligentDecisionEngine, TargetType, TechnologyStack,
    TargetProfile, AttackStep, AttackChain
)
from core.error_handler import (
    IntelligentErrorHandler, GracefulDegradation,
    ErrorType, RecoveryAction, ErrorContext, RecoveryStrategy
)
from core.bug_bounty import BugBountyWorkflowManager, FileUploadTestingFramework
from core.ctf import CTFWorkflowManager, CTFToolManager, CTFChallengeAutomator, CTFTeamCoordinator
from core.optimizer import (
    TechnologyDetector, RateLimitDetector, FailureRecoverySystem,
    PerformanceMonitor, ParameterOptimizer
)
from core.process_manager import (
    ProcessPool, AdvancedCache, ProcessManager, PythonEnvironmentManager,
    ResourceMonitor, PerformanceDashboard, EnhancedProcessManager
)
from core.cve_intelligence import CVEIntelligenceManager
from core.exploit_engine import AIExploitGenerator, VulnerabilityCorrelator
from core.http_testing import HTTPTestingFramework, BrowserAgent
from core.payload import AIPayloadGenerator

# ============================================================================
# SINGLETON INSTANCES (in original order)
# ============================================================================

decision_engine = IntelligentDecisionEngine()
error_handler = IntelligentErrorHandler()
degradation_manager = GracefulDegradation()
bugbounty_manager = BugBountyWorkflowManager()
fileupload_framework = FileUploadTestingFramework()
tech_detector = TechnologyDetector()
rate_limiter = RateLimitDetector()
failure_recovery = FailureRecoverySystem()
performance_monitor = PerformanceMonitor()
parameter_optimizer = ParameterOptimizer()
enhanced_process_manager = EnhancedProcessManager()
ctf_manager = CTFWorkflowManager()
ctf_tools = CTFToolManager()
ctf_automator = CTFChallengeAutomator()
ctf_coordinator = CTFTeamCoordinator()
env_manager = PythonEnvironmentManager()
cve_intelligence = CVEIntelligenceManager()
exploit_generator = AIExploitGenerator()
vulnerability_correlator = VulnerabilityCorrelator()
http_framework = HTTPTestingFramework()
browser_agent = BrowserAgent()
ai_payload_generator = AIPayloadGenerator()
BANNER = ModernVisualEngine.create_banner()
