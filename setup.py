#!/usr/bin/env python3
"""
Setup script for Windows Kernel Driver Logic Flow Analysis Tool
"""

from setuptools import setup, find_packages
import os
from pathlib import Path

# Read version from package
def get_version():
    """Get version from package __init__.py"""
    init_file = Path(__file__).parent / "logic_flow" / "__init__.py"
    if init_file.exists():
        with open(init_file, 'r', encoding='utf-8') as f:
            for line in f:
                if line.startswith('__version__'):
                    return line.split('=')[1].strip().strip('"\'')

    return "3.0.0"  # Fallback

# Read README
def get_long_description():
    """Get long description from README.md"""
    readme_file = Path(__file__).parent / "README.md"
    if readme_file.exists():
        with open(readme_file, 'r', encoding='utf-8') as f:
            return f.read()
    return ""

setup(
    name="logic-flow-analysis",
    version=get_version(),
    author="Security Research Tools",
    author_email="",  # Add if needed
    description="Windows Kernel Driver Logic Flow Analysis Tool",
    long_description=get_long_description(),
    long_description_content_type="text/markdown",
    url="https://github.com/your-repo/logic-flow-analysis",  # Update with actual repo
    packages=find_packages(exclude=["tests", "docs"]),
    include_package_data=True,
    python_requires=">=3.8",
    install_requires=[
        "PyQt6>=6.5.0",
        "PyQt6-Qt6>=6.5.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "black>=22.0.0",
            "flake8>=4.0.0",
            "mypy>=0.950",
        ],
        "gui": [
            # GUI enhancements can be added here
        ],
    },
    entry_points={
        "console_scripts": [
            "logic-flow-analysis=main:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Intended Audience :: Science/Research",
        "License :: OSI Approved :: MIT License",
        "Operating System :: Microsoft :: Windows",
        "Operating System :: POSIX :: Linux",
        "Operating System :: MacOS",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: Software Development :: Debuggers",
        "Topic :: Software Development :: Disassemblers",
    ],
    keywords="ida pro, reverse engineering, windows kernel, driver analysis, security research",
    project_urls={
        "Bug Reports": "https://github.com/your-repo/logic-flow-analysis/issues",
        "Source": "https://github.com/your-repo/logic-flow-analysis",
        "Documentation": "https://github.com/your-repo/logic-flow-analysis#readme",
    },
)
