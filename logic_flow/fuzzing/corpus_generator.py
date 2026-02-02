"""
Corpus Generator.

Generates seed inputs for IOCTL fuzzing based on static analysis data.
"""
import os
import struct
import random
from typing import List, Optional

class CorpusGenerator:
    """
    Generates initial seed corpus for a target IOCTL.
    """
    def __init__(self, output_dir: str):
        self.output_dir = output_dir

    def generate_seeds_for_ioctl(self, ioctl_code: int, input_size: Optional[int] = None) -> List[str]:
        """
        Generate generic seeds for a given IOCTL.
        Returns list of generated file paths.
        """
        seeds = []
        base_name = f"ioctl_{ioctl_code:x}"
        
        # 1. Boundary Sizes (if size unknown, assume generic small sizes)
        sizes = [0, 4, 8, 16, 32, 256, 4096]
        if input_size and input_size > 0:
            sizes = [input_size]
            # Add boundary variations if exact size is known
            if input_size > 4:
                sizes.append(input_size - 1)
                sizes.append(input_size + 1)
                sizes.append(input_size * 2)

        # 2. Pattern Generators
        for size in sizes:
            # All Zeros
            self._write_seed(f"{base_name}_zero_{size}.bin", b'\x00' * size)
            
            # All Ones
            self._write_seed(f"{base_name}_ones_{size}.bin", b'\xFF' * size)
            
            # Alternating
            self._write_seed(f"{base_name}_alt_{size}.bin", b'\xAA\x55' * (size // 2 + 1))
            
            # ASCII / Text (common for symlinks or naming)
            if size > 4:
                self._write_seed(f"{base_name}_txt_{size}.bin", b'A' * size)

        return seeds

    def _write_seed(self, filename: str, data: bytes) -> str:
        """Write byte data to output directory."""
        path = os.path.join(self.output_dir, filename)
        # Ensure dir exists
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'wb') as f:
            f.write(data)
        return path
