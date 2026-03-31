# Windows Kernel Logic Flow Analyzer v3.0 (FastDiff) 🛡️🧠

This platform automates the semantic analysis of Windows Drivers (.sys), combining **Cross-Architecture Binary Diffing**, **Symbolic Execution (angr)**, **Machine Learning**, and **Repository-Scale Search** to detect sophisticated vulnerabilities like **Silent Patches**, **Double-Fetches**, and **Logic Bugs**.

---

## 🚀 Key Capabilities (v3.0)

### 1. Cross-Architecture IR Diffing
*   **Unified IR Normalization**: Abstracts away compiler differences and CPU architectures (x86, x64, ARM, MIPS) to a canonical 42-operator set.
*   **Multi-Stage Matcher**: Exact hashing → Name-guided alignment → Fuzzy IR Histogram Cosine Similarity.
*   **Selective Equivalence**: Uses **Z3 SMT Solver & angr** to formally prove symbolic block equivalence for high-confidence matching.

### 2. Repository-Scale Search (1-to-N)
*   **Fast Index Store**: SQLite-backed persistent sketch store for tracking millions of functions.
*   **Query Pipeline**: 3-stage funnel (`lookup` → `top-K` → `refine`) powered by Winnowing, SimHash, and MinHash.
*   **Domain-Aware Clustering**: Automatically groups drivers into heuristic families (e.g., NDIS, WDF, File Systems, Bluetooth).

### 3. Offensive Research Automation
*   **Automated Exploit Generation (AEG)**: Solves path constraints to generate concrete crash inputs (`poc.bin`).
*   **Taint Analysis**: Tracks data flow from `SystemBuffer` (IOCTL) to dangerous Sinks (`RtlCopyMemory`, `MmMapIoSpace`).
*   **API Taxonomy**: Identifies sink topologies across 11 major attack surfaces (Pool, Registry, File, Memory, etc.).

### 4. High-Performance Core & Interface
*   **Rust Native Core**: Blazing-fast graph algorithms and hashing techniques exposed via `PyO3`.
*   **Headless CLI**: Automate pipeline integration via `python -m logic_flow.cli`.
*   **Modern PyQt6 UI**: Visual split-view diffs and logic shapes to aid manual human inspection.

---

## 💻 Deployment Guide

Follow these steps to deploy the tool on a fresh analyst machine.

### Prerequisites
*   **OS**: Windows 10/11 or Ubuntu.
*   **Python**: Version 3.10 or newer (using `venv`).
*   **Rust**: Standard Toolchain (`rustup`) required for `logic_flow_native`.
*   **C++ Build Tools**: Recommended for compiling ML constraints (Visual Studio Build Tools on Windows).

### Installation Steps

1.  **Clone & Setup Python Environment**
    ```bash
    git clone https://github.com/your-repo/kernel-analyzer.git
    cd kernel-analyzer
    python -m venv venv
    .\venv\Scripts\activate  # Windows
    # source venv/bin/activate # Linux
    ```

2.  **Install Python Dependencies**
    This installs the core GUI, CLI, Py-TLSH, Angr, Z3, and PyTorch.
    ```bash
    pip install -r requirements.txt
    ```
    *Note: `ssdeep` is intentionally disabled on Windows to prevent C-compilation headaches. We rely on the robust `py-tlsh` package for structural hashing instead.*

3.  **Compile the Native Accelerator**
    The core graph algorithms and structural hashes run in Rust for maximum speed.
    ```bash
    cd logic_flow/native_core
    cargo build --release
    cd ../..
    ```
    *The Python engine will automatically load the built bindings.*

4.  **Launch the Tool**
    To run the modernized PyQt6 graphical interface:
    ```bash
    python main.py
    ```
    
    To run the Headless CLI (FastDiff):
    ```bash
    python -m logic_flow.cli --help
    ```

---

## 📂 Developer Structure

*   `logic_flow/`: Main package directory.
    *   `core/`: **The Brain**. Contains components like `IndexStore`, `CrossArchMatcher`, `QueryPipeline`, and `ProtocolV2`.
    *   `gui/`: **Visualization**. PyQt6 interface and modern widgets.
    *   `cli/`: **Headless Mode**. CLI entrypoints.
    *   `pwn/`: **Offensive Modules**. Taint engines, AEG, Double-fetch detection.
    *   `native_core/`: **Rust Source**. High-performance native algorithms (Cargo/PyO3).
*   `tests/`: Comprehensive PyTest suite for verifying cross-arch and core behavior.

---

**Author**: Ancongchua