# Windows Kernel Logic Flow Analyzer v2.3 - Researcher Edition 🛡️🧠

This platform automates the semantic analysis of Windows Drivers (.sys), combining **Symbolic Execution (angr)**, **Machine Learning**, and **Visual Diffing** to detect sophisticated vulnerabilities like **Silent Patches**, **Double-Fetches**, and **Logic Bugs**.

---
## 🚀 Key Capabilities

### 1. Semantic Analysis (Logic > Syntax)
*   **VEX IR Normalization**: Abstracts away compiler differences (Optimization O2/O3) to compare pure logic.
*   **Mathematical Proofs**: Uses **Z3 SMT Solver** to prove equivalence between code blocks (`Output_A == Output_B?`).

### 2. Offensive Research (Pwn)
*   **Automated Exploit Generation (AEG)**: Solves path constraints to generate concrete crash inputs (`poc.bin`).
*   **Taint Analysis**: Tracks data flow from `SystemBuffer` (IOCTL) to dangerous Sinks (`RtlCopyMemory`, `MmMapIoSpace`).
*   **IOCTL Mapping**: Automatically simulates `DriverEntry` to discover the attack surface.

### 3. Visual Intelligence
*   **Split-View Diff**: Side-by-side comparison of patched vs vulnerable drivers.
*   **Logic Shapes**: Visual distinction between Decision Nodes (♦️) and Actions (█).

---

## 💻 Clean Machine Setup (Deployment Guide)

Follow these steps to deploy the tool on a fresh analyst machine.

### Prerequisites
*   **OS**: Windows 10/11 or Linux.
*   **Python**: Version 3.10 or newer.
*   **Rust**: Standard Toolchain (`rustup`).
*   **C++ Build Tools**: Required for compiling `angr`/`py-tlsh` (Visual Studio Build Tools on Windows).

### Installation Steps

1.  **Clone & Setup Python Environment**
    ```bash
    git clone https://github.com/your-repo/kernel-analyzer.git
    cd kernel-analyzer
    python -m venv venv
    .\venv\Scripts\activate  # Windows
    # source venv/bin/activate # Linux
    ```

2.  **Install dependencies (The "Heavy" Suite)**
    This installs the core GUI plus Angr, Z3, PyTorch, and Faiss.
    ```bash
    pip install -r requirements.txt
    ```
    *Tip: This downloads ~1-2GB of ML/Symbolic libraries.*

3.  **Compile Native Accelerator** (For max performance)
    The graph comparison logic runs in Rust.
    ```bash
    cd logic_flow/native_core
    cargo build --release
    cd ../..
    ```
    *The Python engine automatically loads the built `.dll`/`.so`.*

4.  **Launch**
    run main.py with the following command:
    ```bash
    python main.py
    ```

---

## 📂 Developer Structure

*   `logic_flow/`: Main package.
    *   `core/`: **The Brain**. Contains `engine.py` (Coordinator), `advanced_lifter.py` (Angr wrapper), `semantic_diff.py` (Z3 logic).
    *   `pwn/`: **Offensive Modules**. `exploit_generator.py` (AEG), `taint_engine.py` (Data flow), `double_fetch.py`.
    *   `native_core/`: **Rust Source**. High-performance graph algorithms.
    *   `utils/`: **Visualization**. Cytoscape HTML generators.
*   `tests/`: Unit tests and verification scripts.

---

**Author**: Ancongchua