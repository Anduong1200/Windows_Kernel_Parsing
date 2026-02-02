"""
Configuration Manager for Logic Flow Analysis Tool

Handles IDA Pro path detection, configuration persistence, and user settings.
Provides intelligent auto-discovery with fallback to user prompts.
"""

import os
import json
import logging
from pathlib import Path
from typing import Optional, Dict, Any
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class IDAConfig:
    """Configuration for IDA Pro installation."""
    executable_path: Optional[str] = None
    version: Optional[str] = None
    is_configured: bool = False


class ConfigManager:
    """
    Manages application configuration with intelligent IDA Pro detection.

    Features:
    - Auto-detection from common paths and environment variables
    - Configuration persistence to user config directory
    - Registry scanning on Windows
    - Environment variable support (IDA_PATH)
    - User-friendly path selection prompts
    """

    def __init__(self):
        self.config_dir = self._get_config_dir()
        self.config_file = self.config_dir / "config.json"
        self._config = self._load_config()
        self._ida_config = IDAConfig()

        # Initialize IDA detection
        self._detect_ida_path()

    def _get_config_dir(self) -> Path:
        """Get the appropriate config directory for the current OS."""
        if os.name == 'nt':  # Windows
            base_dir = os.environ.get('APPDATA', Path.home() / 'AppData' / 'Roaming')
            config_dir = Path(base_dir) / 'LogicFlowAnalysis'
        else:  # Linux/Mac
            config_dir = Path.home() / '.config' / 'logic_flow_analysis'

        # Ensure directory exists
        config_dir.mkdir(parents=True, exist_ok=True)
        return config_dir

    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from file."""
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError) as e:
                logger.warning(f"Failed to load config file: {e}")
                return {}
        return {}

    def _save_config(self):
        """Save current configuration to file."""
        try:
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(self._config, f, indent=2, ensure_ascii=False)
        except IOError as e:
            logger.error(f"Failed to save config file: {e}")

    def _detect_ida_path(self):
        """Intelligent IDA Pro path detection with multiple strategies."""

        # Strategy 1: Check environment variable
        ida_path = os.environ.get('IDA_PATH')
        if ida_path and self._validate_ida_path(ida_path):
            self._ida_config.executable_path = ida_path
            self._ida_config.is_configured = True
            logger.info(f"IDA Pro found via IDA_PATH environment variable: {ida_path}")
            return

        # Strategy 2: Check saved configuration
        saved_path = self._config.get('ida_path')
        if saved_path and self._validate_ida_path(saved_path):
            self._ida_config.executable_path = saved_path
            self._ida_config.is_configured = True
            logger.info(f"IDA Pro found via saved config: {saved_path}")
            return

        # Strategy 3: Auto-discover from common paths
        common_paths = self._get_common_ida_paths()
        for path in common_paths:
            if self._validate_ida_path(path):
                self._ida_config.executable_path = path
                self._ida_config.is_configured = True
                self.set_ida_path(path)  # Save for future use
                logger.info(f"IDA Pro auto-detected: {path}")
                return

        # Strategy 4: Windows Registry scan (if on Windows)
        if os.name == 'nt':
            registry_path = self._scan_windows_registry()
            if registry_path and self._validate_ida_path(registry_path):
                self._ida_config.executable_path = registry_path
                self._ida_config.is_configured = True
                self.set_ida_path(registry_path)
                logger.info(f"IDA Pro found via Windows Registry: {registry_path}")
                return

        # If no path found, leave unconfigured - user will be prompted later
        logger.info("IDA Pro not found automatically - will prompt user on first use")

    def _get_common_ida_paths(self) -> list[str]:
        """Get list of common IDA Pro installation paths."""
        paths = []

        # Common IDA installation directories (prioritize newer versions)
        ida_dirs = [
            r"C:\Program Files\IDA Pro 9.0",
            r"C:\Program Files\IDA Pro 8.4",
            r"C:\Program Files\IDA Pro 8.3",
            r"C:\Program Files\IDA Pro 8.2",
            r"C:\Program Files\IDA Pro 8.1",
            r"C:\Program Files\IDA Pro 8.0",
            r"C:\Program Files\IDA Pro 7.7",
            r"C:\Program Files\IDA Pro 7.6",
            r"C:\Program Files (x86)\IDA Pro 9.0",
            r"C:\Program Files (x86)\IDA Pro 8.4",
            r"C:\Program Files (x86)\IDA Pro 8.3",
            r"C:\Program Files (x86)\IDA Pro 7.7",
            r"C:\Program Files (x86)\IDA Pro 7.6",
            r"C:\Program Files (x86)\IDA Pro 7.5",
            r"C:\Program Files (x86)\IDA Pro 7.4",
            # Alternative locations
            r"D:\Tools\IDA Pro 9.0",
            r"D:\Tools\IDA Pro 8.4",
            r"D:\Tools\IDA Pro 8.3",
            r"C:\IDA Pro 9.0",
            r"C:\IDA Pro 8.4",
            r"C:\IDA Pro 8.3"
        ]

        # For each IDA directory, check for executables in priority order
        for ida_dir in ida_dirs:
            if os.path.exists(ida_dir):
                # Priority: idat64.exe > idat.exe > ida64.exe > ida.exe
                executables = [
                    os.path.join(ida_dir, "idat64.exe"),  # 64-bit text mode (best)
                    os.path.join(ida_dir, "idat.exe"),    # 32-bit text mode
                    os.path.join(ida_dir, "ida64.exe"),   # 64-bit GUI mode
                    os.path.join(ida_dir, "ida.exe")      # 32-bit GUI mode
                ]

                for exe_path in executables:
                    if os.path.exists(exe_path):
                        paths.append(exe_path)
                        break  # Found one in this directory, move to next

        return paths

    def _scan_windows_registry(self) -> Optional[str]:
        """Scan Windows Registry for IDA Pro installation."""
        try:
            import winreg

            # Common registry keys to check
            registry_keys = [
                r"SOFTWARE\Hex-Rays\IDA Pro",
                r"SOFTWARE\Wow6432Node\Hex-Rays\IDA Pro",
            ]

            for key_path in registry_keys:
                try:
                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
                        # Try to get InstallDir or Path value
                        try:
                            install_dir, _ = winreg.QueryValueEx(key, "InstallDir")
                            ida_exe = os.path.join(install_dir, "ida.exe")
                            if os.path.exists(ida_exe):
                                return ida_exe
                        except FileNotFoundError:
                            pass

                        try:
                            path, _ = winreg.QueryValueEx(key, "Path")
                            if os.path.exists(path):
                                return path
                        except FileNotFoundError:
                            pass

                except FileNotFoundError:
                    continue

        except ImportError:
            logger.debug("winreg module not available - skipping registry scan")

        return None

    def _validate_ida_path(self, path: str) -> bool:
        """Validate if the given path is a valid IDA executable."""
        if not path or not os.path.exists(path):
            return False

        # Check if it's actually an executable
        if os.name == 'nt':
            # Allow both GUI and text mode IDA executables
            valid_executables = ('ida.exe', 'ida64.exe', 'idat.exe', 'idat64.exe')
            return path.lower().endswith(valid_executables) and os.access(path, os.X_OK)
        else:
            return os.access(path, os.X_OK)

    def get_ida_path(self) -> Optional[str]:
        """Get the configured IDA Pro executable path."""
        return self._ida_config.executable_path

    def set_ida_path(self, path: str):
        """Set and persist the IDA Pro executable path."""
        # Normalize path for cross-platform compatibility
        normalized_path = os.path.normpath(path)

        if self._validate_ida_path(normalized_path):
            self._ida_config.executable_path = normalized_path
            self._ida_config.is_configured = True
            self._config['ida_path'] = normalized_path
            self._save_config()
            logger.info(f"IDA Pro path configured: {normalized_path}")
        else:
            raise ValueError(f"Invalid IDA Pro path: {normalized_path}")

    def is_ida_configured(self) -> bool:
        """Check if IDA Pro is properly configured."""
        return self._ida_config.is_configured

    def prompt_for_ida_path(self) -> Optional[str]:
        """
        Prompt user to select IDA Pro executable path.

        This method should be called from the GUI layer when auto-detection fails.
        For now, returns None to indicate that GUI should show a file dialog.
        """
        # Return None to indicate that GUI should prompt user
        # The actual file dialog implementation is in the GUI layer
        return None

    def show_ida_path_selection_dialog(self) -> Optional[str]:
        """
        Show a file selection dialog for IDA executable.
        This should be implemented in the GUI layer using QFileDialog.
        """
        # This is a placeholder for GUI implementation
        # In actual implementation, this would show:
        # QFileDialog.getOpenFileName(
        #     self, "Select IDA Pro Executable",
        #     "", "Executables (*.exe);;All files (*.*)"
        # )
        logger.info("IDA path selection dialog should be shown by GUI layer")
        return None

    def get_config_value(self, key: str, default=None) -> Any:
        """Get a configuration value."""
        return self._config.get(key, default)

    def set_config_value(self, key: str, value: Any):
        """Set and persist a configuration value."""
        self._config[key] = value
        self._save_config()

    def get_log_dir(self) -> Path:
        """Get the logs directory path."""
        log_dir = self.config_dir / "logs"
        log_dir.mkdir(exist_ok=True)
        return log_dir

    def get_temp_dir(self) -> Path:
        """Get the temporary files directory path."""
        temp_dir = self.config_dir / "temp"
        temp_dir.mkdir(exist_ok=True)
        return temp_dir

    # Analysis configuration methods
    def get_max_graph_depth(self) -> int:
        """Get maximum graph traversal depth."""
        return self._config.get('analysis', {}).get('max_graph_depth', 5)

    def get_max_semantic_candidates(self) -> int:
        """Get maximum number of semantic candidates to analyze."""
        return self._config.get('analysis', {}).get('max_semantic_candidates', 20)

    def get_max_comparison_candidates(self) -> int:
        """Get maximum number of candidates for full comparison analysis."""
        return self._config.get('analysis', {}).get('max_comparison_candidates', 10)

    def get_max_graph_nodes(self) -> int:
        """Get maximum number of nodes allowed in a logic graph."""
        return self._config.get('analysis', {}).get('max_graph_nodes', 100)

    def get_downward_traversal_limit(self) -> int:
        """Get limit for downward traversal from anchor function."""
        return self._config.get('analysis', {}).get('downward_traversal_limit', 2)

    def get_min_candidate_score(self) -> float:
        """Get minimum score threshold for meaningful candidates."""
        return self._config.get('analysis', {}).get('min_candidate_score', 3.0)

    def get_high_score_threshold(self) -> float:
        """Get threshold for considering a candidate as high-confidence."""
        return self._config.get('analysis', {}).get('high_score_threshold', 8.0)

    def get_ida_timeout(self) -> int:
        """Get IDA analysis timeout in seconds."""
        return self._config.get('analysis', {}).get('ida_timeout', 300)  # Default 5 minutes

    def set_ida_timeout(self, timeout_seconds: int):
        """Set IDA analysis timeout in seconds."""
        if 'analysis' not in self._config:
            self._config['analysis'] = {}
        self._config['analysis']['ida_timeout'] = timeout_seconds
        self._save_config()

    def set_analysis_config(self, key: str, value: Any):
        """Set an analysis configuration value."""
        if 'analysis' not in self._config:
            self._config['analysis'] = {}
        self._config['analysis'][key] = value
        self._save_config()

    def get_ida_startup_timeout(self) -> int:
        """Get IDA startup/connection timeout in seconds (for socket wait)."""
        return self._config.get('analysis', {}).get('ida_startup_timeout', 60)

    def set_ida_startup_timeout(self, timeout_seconds: int):
        """Set IDA startup timeout in seconds."""
        if 'analysis' not in self._config:
            self._config['analysis'] = {}
        self._config['analysis']['ida_startup_timeout'] = timeout_seconds
        self._save_config()

    def get_socket_host(self) -> str:
        """Get socket host for IDA connection (default localhost, configurable for Docker/VM)."""
        return self._config.get('network', {}).get('socket_host', '127.0.0.1')

    def set_socket_host(self, host: str):
        """Set socket host for IDA connection."""
        if 'network' not in self._config:
            self._config['network'] = {}
        self._config['network']['socket_host'] = host
        self._save_config()