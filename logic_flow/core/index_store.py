"""
Index Store — SQLite-backed persistent storage for function sketches + metadata.

Provides fast lookup of:
  - Binary metadata (SHA256, filename, family, func count)
  - Function sketches (opcode hash, callee names, size)
  - Family-grouped search

Schema is tuned for the query pipeline: hash-exact lookups + range scans.
Zero external dependencies (stdlib sqlite3 only).
"""

from __future__ import annotations
import json
import logging
import sqlite3
import time
from dataclasses import dataclass
from typing import Dict, List, Optional

from .protocol_v2 import DriverAnalysisExportV2
from .fuzzy_hash import compute_opcode_hash
from .driver_families import classify_driver

logger = logging.getLogger(__name__)

# Default DB path
DEFAULT_DB_PATH = "fastdiff_index.db"


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------
@dataclass
class BinaryRecord:
    """Row from the binaries table."""
    sha256: str
    filename: str
    arch: str = "x64"
    file_format: str = "PE"
    driver_family: str = ""
    func_count: int = 0
    import_count: int = 0
    indexed_at: str = ""
    metadata_json: str = ""


@dataclass
class FunctionSketch:
    """Row from the function_sketches table."""
    id: int = 0
    binary_sha256: str = ""
    func_ea: int = 0
    func_name: str = ""
    func_size: int = 0
    is_import: bool = False
    opcode_hash: str = ""
    mnemonic_sig: str = ""
    call_count: int = 0
    callee_names: str = "[]"


# ---------------------------------------------------------------------------
# Index Store
# ---------------------------------------------------------------------------
class IndexStore:
    """
    SQLite-backed index for binary sketches and metadata.

    Usage:
        store = IndexStore("my_index.db")
        store.index_binary(export, family="ndis")
        results = store.search_by_opcode_hash(hash_str, limit=10)
        store.close()
    """

    def __init__(self, db_path: str = DEFAULT_DB_PATH):
        self.db_path = db_path
        self._conn: Optional[sqlite3.Connection] = None
        self._ensure_schema()

    @property
    def conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = sqlite3.connect(self.db_path)
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
        return self._conn

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None

    def _ensure_schema(self) -> None:
        """Create tables and indexes if they don't exist."""
        c = self.conn
        c.executescript("""
            CREATE TABLE IF NOT EXISTS binaries (
                sha256        TEXT PRIMARY KEY,
                filename      TEXT NOT NULL,
                arch          TEXT DEFAULT 'x64',
                file_format   TEXT DEFAULT 'PE',
                driver_family TEXT DEFAULT '',
                func_count    INTEGER DEFAULT 0,
                import_count  INTEGER DEFAULT 0,
                indexed_at    TEXT NOT NULL,
                metadata_json TEXT DEFAULT '{}'
            );

            CREATE TABLE IF NOT EXISTS function_sketches (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                binary_sha256 TEXT NOT NULL REFERENCES binaries(sha256) ON DELETE CASCADE,
                func_ea       INTEGER NOT NULL,
                func_name     TEXT NOT NULL,
                func_size     INTEGER DEFAULT 0,
                is_import     BOOLEAN DEFAULT 0,
                opcode_hash   TEXT DEFAULT '',
                mnemonic_sig  TEXT DEFAULT '',
                call_count    INTEGER DEFAULT 0,
                callee_names  TEXT DEFAULT '[]',
                UNIQUE(binary_sha256, func_ea)
            );

            CREATE INDEX IF NOT EXISTS idx_sketches_sha ON function_sketches(binary_sha256);
            CREATE INDEX IF NOT EXISTS idx_sketches_hash ON function_sketches(opcode_hash);
            CREATE INDEX IF NOT EXISTS idx_sketches_name ON function_sketches(func_name);
            CREATE INDEX IF NOT EXISTS idx_binaries_family ON binaries(driver_family);
        """)
        c.commit()
        # Migrate: add IR columns if missing (for existing databases)
        self._migrate_ir_columns()

    def _migrate_ir_columns(self) -> None:
        """Add ir_hash / ir_histogram columns if they don't exist (schema v2)."""
        c = self.conn
        existing = {
            row[1]
            for row in c.execute("PRAGMA table_info(function_sketches)").fetchall()
        }
        if "ir_hash" not in existing:
            c.execute(
                "ALTER TABLE function_sketches ADD COLUMN ir_hash TEXT DEFAULT ''"
            )
        if "ir_histogram" not in existing:
            c.execute(
                "ALTER TABLE function_sketches "
                "ADD COLUMN ir_histogram TEXT DEFAULT '{}'"
            )
        c.commit()

    # ── Binary operations ──────────────────────────────────────────────

    def index_binary(
        self,
        export: DriverAnalysisExportV2,
        family: Optional[str] = None,
    ) -> BinaryRecord:
        """
        Index a complete binary export into the store.

        If the binary is already indexed (by SHA256), it is updated.

        Args:
            export: The driver export to index
            family: Override family classification (auto-detected if None)

        Returns:
            BinaryRecord for the indexed binary
        """
        t0 = time.perf_counter()
        meta = export.metadata

        # Auto-classify if family not provided
        if family is None:
            classification = classify_driver(export)
            family = classification.family.value
            logger.info(f"Auto-classified as: {classification}")

        sha256 = meta.binary_sha256
        if not sha256:
            # Generate a synthetic SHA from filename + func count
            import hashlib
            sha256 = hashlib.sha256(
                f"{meta.input_file}:{len(export.functions)}".encode()
            ).hexdigest()

        # Build callee index from call graph
        callees: Dict[int, List[str]] = {}
        for cs in export.call_graph:
            if cs.target_name:
                callees.setdefault(cs.caller_ea, []).append(cs.target_name)

        indexed_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        metadata_json = json.dumps({
            "schema_version": meta.schema_version,
            "tool": meta.tool,
            "arch": meta.arch,
            "file_format": meta.file_format,
            "timestamp": meta.timestamp,
        })

        # Import count
        import_count = len(export.imports)

        # Non-import function count
        func_count = sum(1 for fi in export.functions.values() if not fi.is_import)

        # Upsert binary record
        self.conn.execute("""
            INSERT INTO binaries (sha256, filename, arch, file_format, driver_family,
                                  func_count, import_count, indexed_at, metadata_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(sha256) DO UPDATE SET
                filename=excluded.filename,
                driver_family=excluded.driver_family,
                func_count=excluded.func_count,
                import_count=excluded.import_count,
                indexed_at=excluded.indexed_at,
                metadata_json=excluded.metadata_json
        """, (
            sha256, meta.input_file, meta.arch, meta.file_format,
            family, func_count, import_count, indexed_at, metadata_json,
        ))

        # Delete old sketches for this binary (in case of re-index)
        self.conn.execute(
            "DELETE FROM function_sketches WHERE binary_sha256 = ?", (sha256,)
        )

        # Insert function sketches
        sketch_rows = []
        for ea_str, fi in export.functions.items():
            # Compute opcode hash from instructions
            opcode_hash = ""
            mnemonic_sig = ""
            insns = export.function_instructions.get(ea_str, [])
            if insns:
                mnemonics = [i.mnemonic for i in insns if i.mnemonic]
                if mnemonics:
                    opcode_hash = compute_opcode_hash(mnemonics)
                    # Compact mnemonic signature (first 50 mnemonics)
                    mnemonic_sig = ",".join(mnemonics[:50])

            func_callees = callees.get(fi.ea, [])
            callee_json = json.dumps(func_callees)

            sketch_rows.append((
                sha256, fi.ea, fi.name, fi.size, fi.is_import,
                opcode_hash, mnemonic_sig, len(func_callees), callee_json,
            ))

        self.conn.executemany("""
            INSERT INTO function_sketches
                (binary_sha256, func_ea, func_name, func_size, is_import,
                 opcode_hash, mnemonic_sig, call_count, callee_names)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, sketch_rows)

        self.conn.commit()

        elapsed = time.perf_counter() - t0
        logger.info(
            f"Indexed {meta.input_file}: {len(sketch_rows)} sketches "
            f"({family}) in {elapsed:.3f}s"
        )

        return BinaryRecord(
            sha256=sha256,
            filename=meta.input_file,
            arch=meta.arch,
            file_format=meta.file_format,
            driver_family=family,
            func_count=func_count,
            import_count=import_count,
            indexed_at=indexed_at,
            metadata_json=metadata_json,
        )

    def lookup_binary(self, sha256: str) -> Optional[BinaryRecord]:
        """Check if a binary is already indexed."""
        row = self.conn.execute(
            "SELECT * FROM binaries WHERE sha256 = ?", (sha256,)
        ).fetchone()
        if row is None:
            return None
        return self._row_to_binary_record(row)

    def list_binaries(
        self, family: Optional[str] = None, limit: int = 100,
    ) -> List[BinaryRecord]:
        """List indexed binaries, optionally filtered by family."""
        if family:
            rows = self.conn.execute(
                "SELECT * FROM binaries WHERE driver_family = ? "
                "ORDER BY indexed_at DESC LIMIT ?",
                (family, limit),
            ).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM binaries ORDER BY indexed_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [self._row_to_binary_record(r) for r in rows]

    def delete_binary(self, sha256: str) -> bool:
        """Remove a binary and its sketches from the index."""
        # CASCADE delete handles sketches if enabled, but let's be explicit
        self.conn.execute(
            "DELETE FROM function_sketches WHERE binary_sha256 = ?", (sha256,)
        )
        cursor = self.conn.execute(
            "DELETE FROM binaries WHERE sha256 = ?", (sha256,)
        )
        self.conn.commit()
        deleted = cursor.rowcount > 0
        if deleted:
            logger.info(f"Deleted binary {sha256[:16]}... from index")
        return deleted

    def get_binary_count(self) -> int:
        """Number of indexed binaries."""
        row = self.conn.execute("SELECT COUNT(*) FROM binaries").fetchone()
        return row[0]

    # ── Function sketch operations ───────────────────────────────────

    def get_function_sketches(
        self, sha256: str, include_imports: bool = False,
    ) -> List[FunctionSketch]:
        """Get all function sketches for a binary."""
        query = "SELECT * FROM function_sketches WHERE binary_sha256 = ?"
        if not include_imports:
            query += " AND is_import = 0"
        query += " ORDER BY func_ea"
        rows = self.conn.execute(query, (sha256,)).fetchall()
        return [self._row_to_sketch(r) for r in rows]

    def search_by_opcode_hash(
        self,
        opcode_hash: str,
        limit: int = 20,
        exclude_sha256: Optional[str] = None,
        family: Optional[str] = None,
    ) -> List[FunctionSketch]:
        """
        Find functions with an exact opcode hash match.

        Args:
            opcode_hash: The LSH hash string to search for
            limit: Max results
            exclude_sha256: Exclude results from this binary
            family: Only search within this driver family
        """
        params: list = [opcode_hash]
        query = """
            SELECT fs.*
            FROM function_sketches fs
            JOIN binaries b ON fs.binary_sha256 = b.sha256
            WHERE fs.opcode_hash = ?
        """
        if exclude_sha256:
            query += " AND fs.binary_sha256 != ?"
            params.append(exclude_sha256)
        if family:
            query += " AND b.driver_family = ?"
            params.append(family)
        query += " LIMIT ?"
        params.append(limit)

        rows = self.conn.execute(query, params).fetchall()
        return [self._row_to_sketch(r) for r in rows]

    def search_by_name(
        self,
        pattern: str,
        family: Optional[str] = None,
        limit: int = 50,
    ) -> List[FunctionSketch]:
        """Search functions by name (LIKE pattern)."""
        params: list = [f"%{pattern}%"]
        query = """
            SELECT fs.*
            FROM function_sketches fs
            JOIN binaries b ON fs.binary_sha256 = b.sha256
            WHERE fs.func_name LIKE ?
              AND fs.is_import = 0
        """
        if family:
            query += " AND b.driver_family = ?"
            params.append(family)
        query += " LIMIT ?"
        params.append(limit)

        rows = self.conn.execute(query, params).fetchall()
        return [self._row_to_sketch(r) for r in rows]

    def search_similar_functions(
        self,
        opcode_hash: str,
        exclude_sha256: Optional[str] = None,
        family: Optional[str] = None,
        limit: int = 20,
    ) -> List[tuple[FunctionSketch, int]]:
        """
        Search for similar functions by retrieving candidates with the
        same length bucket prefix and comparing hash similarity.

        Returns list of (sketch, similarity_score) tuples.
        """
        # Extract length bucket from hash (e.g. "L5|TA:2|..." -> "L5")
        if not opcode_hash or "|" not in opcode_hash:
            return []

        len_bucket = opcode_hash.split("|")[0]

        # Find candidates with same length bucket
        params: list = [f"{len_bucket}|%"]
        query = """
            SELECT fs.*
            FROM function_sketches fs
            JOIN binaries b ON fs.binary_sha256 = b.sha256
            WHERE fs.opcode_hash LIKE ?
              AND fs.is_import = 0
        """
        if exclude_sha256:
            query += " AND fs.binary_sha256 != ?"
            params.append(exclude_sha256)
        if family:
            query += " AND b.driver_family = ?"
            params.append(family)
        query += " LIMIT 200"  # get generous candidates then score

        rows = self.conn.execute(query, params).fetchall()
        sketches = [self._row_to_sketch(r) for r in rows]

        # Score each candidate
        results: list[tuple[FunctionSketch, int]] = []
        for sk in sketches:
            from .fuzzy_hash import compare_opcode_hash
            score = compare_opcode_hash(opcode_hash, sk.opcode_hash)
            if score > 0:
                results.append((sk, score))

        # Sort by score descending
        results.sort(key=lambda x: x[1], reverse=True)
        return results[:limit]

    # ── Family statistics ─────────────────────────────────────────────

    def get_family_stats(self) -> Dict[str, int]:
        """Get count of binaries per driver family."""
        rows = self.conn.execute("""
            SELECT driver_family, COUNT(*) as cnt
            FROM binaries
            GROUP BY driver_family
            ORDER BY cnt DESC
        """).fetchall()
        return {row["driver_family"]: row["cnt"] for row in rows}

    def get_total_sketch_count(self) -> int:
        """Total number of function sketches in the index."""
        row = self.conn.execute(
            "SELECT COUNT(*) FROM function_sketches WHERE is_import = 0"
        ).fetchone()
        return row[0]

    # ── Row conversion helpers ────────────────────────────────────────

    def _row_to_binary_record(self, row: sqlite3.Row) -> BinaryRecord:
        return BinaryRecord(
            sha256=row["sha256"],
            filename=row["filename"],
            arch=row["arch"],
            file_format=row["file_format"],
            driver_family=row["driver_family"],
            func_count=row["func_count"],
            import_count=row["import_count"],
            indexed_at=row["indexed_at"],
            metadata_json=row["metadata_json"],
        )

    def _row_to_sketch(self, row: sqlite3.Row) -> FunctionSketch:
        return FunctionSketch(
            id=row["id"],
            binary_sha256=row["binary_sha256"],
            func_ea=row["func_ea"],
            func_name=row["func_name"],
            func_size=row["func_size"],
            is_import=bool(row["is_import"]),
            opcode_hash=row["opcode_hash"],
            mnemonic_sig=row["mnemonic_sig"],
            call_count=row["call_count"],
            callee_names=row["callee_names"],
        )
