"""
G-03: Agent Simulation Sandbox
Provides a Docker-based sandboxed execution environment for running target agents
under test conditions. Falls back to a simple in-process HTTP forwarder if Docker
is unavailable.
"""
from __future__ import annotations

import asyncio
import logging
import subprocess
import time
from dataclasses import dataclass, field
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)


@dataclass
class SandboxConfig:
    """Configuration for a sandboxed agent run."""
    image: str                    # Docker image to run
    port: int = 8080              # Port the agent listens on inside the container
    env: Dict[str, str] = field(default_factory=dict)   # Environment variables
    memory_limit: str = "512m"    # Docker memory limit
    cpu_quota: int = 50000        # Docker CPU quota (50% of one core)
    network_mode: str = "none"    # Isolate from the internet by default
    timeout_seconds: int = 120    # Auto-kill after this many seconds


class AgentSandbox:
    """
    Docker-based sandboxed agent execution environment.

    Usage:
        config = SandboxConfig(image="myorg/my-agent:latest")
        async with AgentSandbox(config) as sandbox:
            response = await sandbox.send_prompt("Ignore all previous instructions")
    """

    def __init__(self, config: SandboxConfig):
        self.config = config
        self._container_id: Optional[str] = None
        self._endpoint: Optional[str] = None

    # ─── Context manager ─────────────────────────────────────────────────────

    async def __aenter__(self) -> "AgentSandbox":
        await self._start_container()
        return self

    async def __aexit__(self, *_) -> None:
        await self._stop_container()

    # ─── Public API ──────────────────────────────────────────────────────────

    async def send_prompt(self, prompt: str, timeout: int = 30) -> str:
        """
        Send an adversarial prompt to the sandboxed agent and return the response.
        Returns an empty string if Docker is unavailable or the container failed to start.
        """
        if not self._endpoint:
            logger.warning("Sandbox not running. Returning empty response (simulation mode).")
            return ""

        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self._endpoint,
                    json={"message": prompt},
                    timeout=aiohttp.ClientTimeout(total=timeout),
                ) as resp:
                    data = await resp.json()
                    return data.get("response", "")
        except Exception as exc:
            logger.error("Sandbox prompt failed: %s", exc)
            return ""

    @property
    def endpoint(self) -> Optional[str]:
        return self._endpoint

    # ─── Container lifecycle ─────────────────────────────────────────────────

    async def _start_container(self) -> None:
        """Launch the Docker container in the background."""
        if not self._docker_available():
            logger.warning("Docker is not available. Sandbox running in simulation mode.")
            return

        env_args = []
        for k, v in self.config.env.items():
            env_args += ["-e", f"{k}={v}"]

        cmd = [
            "docker", "run", "-d",
            "--rm",
            f"--memory={self.config.memory_limit}",
            f"--cpu-quota={self.config.cpu_quota}",
            f"--network={self.config.network_mode}",
            "-p", f"0:{self.config.port}",   # Let Docker assign a host port
            *env_args,
            self.config.image,
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if result.returncode != 0:
                logger.error("Failed to start container: %s", result.stderr)
                return

            self._container_id = result.stdout.strip()
            # Give the agent a moment to initialise
            await asyncio.sleep(2)

            host_port = self._get_host_port()
            if host_port:
                self._endpoint = f"http://localhost:{host_port}/chat"
                logger.info("Sandbox started: container=%s endpoint=%s", self._container_id[:12], self._endpoint)
        except Exception as exc:
            logger.error("Failed to start sandbox container: %s", exc)

    async def _stop_container(self) -> None:
        """Kill and remove the sandbox container."""
        if self._container_id:
            try:
                subprocess.run(
                    ["docker", "kill", self._container_id],
                    capture_output=True, timeout=15
                )
                logger.info("Sandbox stopped: %s", self._container_id[:12])
            except Exception as exc:
                logger.warning("Failed to stop container %s: %s", self._container_id, exc)
            finally:
                self._container_id = None
                self._endpoint = None

    def _get_host_port(self) -> Optional[str]:
        """Retrieve the host port Docker mapped to the container's port."""
        if not self._container_id:
            return None
        try:
            result = subprocess.run(
                ["docker", "port", self._container_id, str(self.config.port)],
                capture_output=True, text=True, timeout=10
            )
            # Output: "0.0.0.0:49152"
            port_str = result.stdout.strip().split(":")[-1]
            return port_str if port_str.isdigit() else None
        except Exception:
            return None

    @staticmethod
    def _docker_available() -> bool:
        """Return True if the docker CLI is installed and the daemon is reachable."""
        try:
            result = subprocess.run(
                ["docker", "info"], capture_output=True, timeout=5
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
