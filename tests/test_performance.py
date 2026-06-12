# SPDX-FileCopyrightText: 2026 Pedro Sordo Martínez <amurlaniakea@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Performance Tests — MCP Security Proxy

Benchmarks para verificar que el pipeline no introduce latencia inaceptable.
Los papers de referencia reportan overhead < 50ms por herramienta.
"""

import pytest
import sys
import os
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from policy_engine import MCPSecurityPolicyEngine
from validators import MCPSchemaValidator
from detectors import DCIChecker, TDPDetector
from pipeline import MCPSecurityProxy


# ──────────────────────────────────────────────
# Fixtures
# ──────────────────────────────────────────────

@pytest.fixture
def sample_tool_description():
    return {
        "name": "read_file",
        "description": "Reads a file from the filesystem and returns its content",
        "parameters": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "File path"},
                "encoding": {"type": "string", "description": "Encoding"},
            },
            "required": ["path"],
        },
    }


@pytest.fixture
def sample_input():
    return {"path": "/home/sil/test.txt", "encoding": "utf-8"}


@pytest.fixture
def full_proxy():
    return MCPSecurityProxy(
        allowlist=["filesystem::read_file", "git::*", "web::fetch"],
        schema={
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "encoding": {"type": "string"},
            },
            "required": ["path"],
        },
    )


# ──────────────────────────────────────────────
# Benchmarks por fase individual
# ──────────────────────────────────────────────

class TestPhasePerformance:
    """Cada fase debe completarse en < 10ms."""

    def test_policy_engine_latency(self, sample_tool_description):
        """Policy Engine: < 1ms por check."""
        engine = MCPSecurityPolicyEngine(
            allowlist=["filesystem::read_file", "git::*"]
        )
        times = []
        for _ in range(100):
            start = time.perf_counter()
            engine.check("filesystem::read_file")
            elapsed = (time.perf_counter() - start) * 1000
            times.append(elapsed)
        avg = sum(times) / len(times)
        assert avg < 1.0, "Policy Engine avg {:.3f}ms exceeds 1ms".format(avg)

    def test_schema_validator_latency(self, sample_input):
        """Schema Validator: < 1ms por validacion."""
        validator = MCPSchemaValidator(schema={
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "encoding": {"type": "string"},
            },
            "required": ["path"],
        })
        times = []
        for _ in range(100):
            start = time.perf_counter()
            validator.validate_input(sample_input)
            elapsed = (time.perf_counter() - start) * 1000
            times.append(elapsed)
        avg = sum(times) / len(times)
        assert avg < 1.0, "Schema Validator avg {:.3f}ms exceeds 1ms".format(avg)

    def test_dci_checker_latency(self, sample_tool_description):
        """DCI Checker: < 5ms por analisis."""
        checker = DCIChecker()
        times = []
        for _ in range(100):
            start = time.perf_counter()
            checker.check(sample_tool_description, ["path", "encoding"])
            elapsed = (time.perf_counter() - start) * 1000
            times.append(elapsed)
        avg = sum(times) / len(times)
        assert avg < 5.0, "DCI Checker avg {:.3f}ms exceeds 5ms".format(avg)

    def test_tdp_detector_latency(self, sample_tool_description):
        """TDP Detector: < 5ms por scan."""
        detector = TDPDetector()
        times = []
        for _ in range(100):
            start = time.perf_counter()
            detector.check(sample_tool_description)
            elapsed = (time.perf_counter() - start) * 1000
            times.append(elapsed)
        avg = sum(times) / len(times)
        assert avg < 5.0, "TDP Detector avg {:.3f}ms exceeds 5ms".format(avg)


class TestFullPipelinePerformance:
    """Pipeline completo debe ser < 50ms por herramienta."""

    def test_full_pipeline_latency(self, full_proxy, sample_tool_description, sample_input):
        """Pipeline completo (policy + schema + dci + tdp): < 20ms."""
        times = []
        for _ in range(100):
            start = time.perf_counter()
            full_proxy.check(
                tool_name="filesystem::read_file",
                tool_description=sample_tool_description,
                code_params=["path", "encoding"],
                input_data=sample_input,
            )
            elapsed = (time.perf_counter() - start) * 1000
            times.append(elapsed)
        avg = sum(times) / len(times)
        p95 = sorted(times)[int(len(times) * 0.95)]
        assert avg < 20.0, "Pipeline avg {:.3f}ms exceeds 20ms".format(avg)
        assert p95 < 50.0, "Pipeline p95 {:.3f}ms exceeds 50ms".format(p95)

    def test_pipeline_throughput(self, full_proxy, sample_tool_description, sample_input):
        """Pipeline debe soportar > 100 checks/segundo."""
        duration = 1.0  # 1 segundo
        count = 0
        start = time.perf_counter()
        while time.perf_counter() - start < duration:
            full_proxy.check(
                tool_name="filesystem::read_file",
                tool_description=sample_tool_description,
                code_params=["path", "encoding"],
                input_data=sample_input,
            )
            count += 1
        assert count > 100, "Throughput {} checks/s below 100/s".format(count)


class TestScalability:
    """El rendimiento no debe degradarse con mas herramientas en allowlist."""

    def test_policy_engine_scalability(self):
        """Policy Engine con 1000 herramientas en allowlist."""
        allowlist = ["tool_{}::action".format(i) for i in range(1000)]
        engine = MCPSecurityPolicyEngine(allowlist=allowlist)
        times = []
        for _ in range(100):
            start = time.perf_counter()
            engine.check("tool_999::action")
            elapsed = (time.perf_counter() - start) * 1000
            times.append(elapsed)
        avg = sum(times) / len(times)
        assert avg < 2.0, "Policy Engine with 1000 tools avg {:.3f}ms exceeds 2ms".format(avg)

    def test_tdp_scalability_long_description(self):
        """TDP con descripcion muy larga (10KB)."""
        detector = TDPDetector()
        long_desc = {
            "name": "big_tool",
            "description": "A tool. " + "x" * 10000,
            "parameters": {
                "type": "object",
                "properties": {"input": {"type": "string"}},
                "required": ["input"],
            },
        }
        times = []
        for _ in range(50):
            start = time.perf_counter()
            detector.check(long_desc)
            elapsed = (time.perf_counter() - start) * 1000
            times.append(elapsed)
        avg = sum(times) / len(times)
        assert avg < 10.0, "TDP with 10KB desc avg {:.3f}ms exceeds 10ms".format(avg)
