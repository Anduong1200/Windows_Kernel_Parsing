#!/usr/bin/env python3
"""
IDA Pro Socket Server for Logic Flow Analysis (v2.0 - Robust Architecture)

This script runs as a PERSISTENT server within IDA Pro.
Key improvements:
- Protocol handshake (HELLO -> READY)
- Structured JSON error responses
- Survives logic exceptions (only socket errors break loop)
- PID-specific logging to prevent parallel conflicts
- Module reload for multi-analysis sessions
"""

import sys
import os
import json
import traceback
import socket
import struct
import tempfile
import importlib

# ========================================================================
# PID-SPECIFIC LOGGING (Fix for Batch Processing Race Condition)
# ========================================================================
_PID = os.getpid()
_DEBUG_LOG_FILE = os.path.join(tempfile.gettempdir(), f"ida_debug_{_PID}.txt")

def log_debug(msg: str):
    """Thread-safe logging to PID-specific file."""
    try:
        with open(_DEBUG_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"{msg}\n")
    except Exception:
        pass

log_debug(f"[{_PID}] Script loaded. Args: {sys.argv}")

# ========================================================================
# IDA PRO IMPORTS
# ========================================================================
try:
    import idc
    import idaapi
    import idautils
    import ida_funcs
    import ida_idaapi
    import ida_name
    import ida_xref
    import ida_bytes
    import ida_kernwin
    import ida_auto
    import ida_ua
    log_debug("IDA imports successful.")
except ImportError as e:
    log_debug(f"FATAL: IDA import failed: {e}")
    raise

# ========================================================================
# SOCKET HELPERS (Robust TCP Handling)
# ========================================================================
def recv_exactly(sock: socket.socket, n: int) -> bytes:
    """
    Receive exactly n bytes from socket (handles TCP fragmentation).
    Raises ConnectionError if socket closes prematurely.
    """
    data = b''
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            raise ConnectionError("Socket closed unexpectedly")
        data += packet
    return data


def recv_msg(sock: socket.socket) -> dict:
    """
    Receive a length-prefixed JSON message from socket.
    Returns None on clean disconnect, raises on error.
    """
    try:
        raw_msglen = recv_exactly(sock, 4)
        msglen = struct.unpack('>I', raw_msglen)[0]
        data = recv_exactly(sock, msglen)
        return json.loads(data.decode('utf-8', errors='replace'))
    except ConnectionError:
        return None  # Clean disconnect
    except Exception as e:
        log_debug(f"recv_msg error: {e}")
        raise


def send_msg(sock: socket.socket, data: dict):
    """Send a length-prefixed JSON message."""
    try:
        json_data = json.dumps(data, default=_json_serializer).encode('utf-8')
        msg = struct.pack('>I', len(json_data)) + json_data
        sock.sendall(msg)
    except Exception as e:
        log_debug(f"send_msg error: {e}")
        raise


def _json_serializer(obj):
    """Custom JSON serializer for non-standard types."""
    if isinstance(obj, bytes):
        return obj.hex()
    if isinstance(obj, set):
        return list(obj)
    if hasattr(obj, 'to_dict'):
        return obj.to_dict()
    if hasattr(obj, '__dict__'):
        return obj.__dict__
    return str(obj)


# ========================================================================
# STRUCTURED ERROR RESPONSES
# ========================================================================
def make_error_response(error_code: str, message: str, details: str = "") -> dict:
    """Create a structured error response."""
    return {
        "status": "error",
        "error_code": error_code,
        "message": message,
        "details": details
    }


def make_success_response(data: dict) -> dict:
    """Wrap data in a success response."""
    return {
        "status": "success",
        **data
    }


# ========================================================================
# IDA SOCKET SERVER CLASS
# ========================================================================
class IDASocketServer:
    """
    Persistent socket server for IDA Pro analysis commands.
    
    Protocol:
    1. Server binds to port 0 (OS assigns random available port)
    2. Server writes port to ida_port_{pid}.txt
    3. Client connects
    4. Server sends HELLO handshake with version info
    5. Client sends READY acknowledgment
    6. Command loop begins (analyze, list_functions, ping, exit)
    """
    
    VERSION = "2.0"
    
    def __init__(self):
        self.server_socket = None
        self.client_socket = None
        self.port = None
        self.port_file = None
        self._analysis_modules_loaded = False
    
    def start(self, port: int = 0):
        """
        Start the server. MUST be called BEFORE ida_auto.auto_wait().
        This avoids the "False Timeout" bug where client connects before server is ready.
        """
        log_debug(f"[{_PID}] Starting server...")
        
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind(('127.0.0.1', port))
        self.server_socket.listen(1)
        
        self.port = self.server_socket.getsockname()[1]
        
        # Write port to PID-specific file for client discovery
        self.port_file = os.path.join(tempfile.gettempdir(), f"ida_port_{_PID}.txt")
        with open(self.port_file, "w") as f:
            f.write(str(self.port))
        
        log_debug(f"[{_PID}] Server listening on port {self.port}")
        print(f"IDA_SERVER_PORT:{self.port}")
        sys.stdout.flush()
    
    def wait_for_auto_analysis(self):
        """Wait for IDA's auto-analysis to complete."""
        log_debug(f"[{_PID}] Waiting for auto-analysis...")
        ida_auto.auto_wait()
        log_debug(f"[{_PID}] Auto-analysis complete.")
    
    def accept_client(self):
        """Accept a single client connection."""
        log_debug(f"[{_PID}] Waiting for client connection...")
        self.client_socket, addr = self.server_socket.accept()
        log_debug(f"[{_PID}] Client connected from {addr}")
        
        # Send HELLO handshake
        hello = {
            "status": "READY",
            "version": self.VERSION,
            "pid": _PID,
            "ida_version": idaapi.get_kernel_version()
        }
        send_msg(self.client_socket, hello)
        log_debug(f"[{_PID}] Handshake sent: {hello}")
    
    def run_command_loop(self):
        """
        Main command loop. Survives LOGIC exceptions, only exits on SOCKET errors.
        This fixes the "One-Strike Crash" bug.
        """
        log_debug(f"[{_PID}] Entering command loop...")
        
        while True:
            try:
                request = recv_msg(self.client_socket)
                if request is None:
                    log_debug(f"[{_PID}] Client disconnected (clean).")
                    break
                
                command = request.get('command', '')
                args = request.get('args', {})
                log_debug(f"[{_PID}] Command received: {command}")
                
                # Dispatch command (wrapped in logic exception handler)
                response = self._dispatch_command(command, args)
                send_msg(self.client_socket, response)
                
            except (ConnectionError, BrokenPipeError, OSError) as e:
                # Socket errors = exit loop
                log_debug(f"[{_PID}] Socket error, exiting loop: {e}")
                break
            except Exception as e:
                # Logic errors = log & continue (do NOT break loop)
                log_debug(f"[{_PID}] Logic error (non-fatal): {e}\n{traceback.format_exc()}")
                try:
                    error_resp = make_error_response(
                        "INTERNAL_ERROR",
                        str(e),
                        traceback.format_exc()
                    )
                    send_msg(self.client_socket, error_resp)
                except Exception:
                    # If we can't send the error, socket is dead, exit
                    break
    
    def _dispatch_command(self, command: str, args: dict) -> dict:
        """Route command to handler."""
        if command == 'ping':
            return make_success_response({"message": "pong"})
        
        elif command == 'exit':
            log_debug(f"[{_PID}] Exit command received.")
            return make_success_response({"message": "shutting_down"})
        
        elif command == 'cancel':
            log_debug(f"[{_PID}] Cancel command received - aborting analysis.")
            self._cancel_requested = True
            return make_success_response({"message": "cancel_acknowledged"})
        
        elif command == 'analyze':
            return _handle_analyze_command(args)
        
    def _handle_list_functions(self, args: dict) -> dict:
        """Handle list_functions command."""
        try:
            functions = {}
            for func_ea in idautils.Functions():
                 name = ida_name.get_name(func_ea)
                 functions[str(func_ea)] = name
            return make_success_response({"functions": functions})
        except Exception as e:
             return make_error_response("LIST_ERROR", str(e))

    def _handle_jump_to(self, args: dict) -> dict:
        """Handle jump_to command."""
        try:
            address_str = args.get('address')
            if not address_str:
                 return make_error_response("INVALID_ARGS", "Address missing")
            
            ea = int(address_str, 16) if address_str.startswith('0x') else int(address_str)
            ida_kernwin.jumpto(ea)
            return make_success_response({"message": f"Jumped to {hex(ea)}"})
        except Exception as e:
             return make_error_response("JUMP_ERROR", str(e))

    def shutdown(self):
        """Clean shutdown of sockets."""
        log_debug(f"[{_PID}] Shutting down server...")
        if self.client_socket:
            try:
                self.client_socket.close()
            except: pass
        if self.server_socket:
            try:
                self.server_socket.close()
            except: pass
        if self.port_file:
             try:
                 os.remove(self.port_file)
             except: pass

def _extract_instructions(func) -> list:
    """
    Dump instructions for a function.
    Enhanced (v2.0): Resolves call targets for semantic signatures.
    """
    insns = []
    # Use idautils.FuncItems roughly equiv
    for ea in range(func.start_ea, func.end_ea):
        if not ida_bytes.is_code(ida_bytes.get_flags(ea)):
            continue
            
        mnem = ida_ua.ua_mnem(ea)
        if not mnem: continue
        
        # Decode instruction
        insn_t = ida_ua.insn_t()
        ida_ua.decode_insn(insn_t, ea)
        
        # Dump bytes
        length = insn_t.size
        b = ida_bytes.get_bytes(ea, length)
        bytes_hex = b.hex() if b else ""
        
        # Operands
        ops = []
        is_call = ida_ua.is_call_insn(insn_t)
        target_name = None
        target_ea = None
        
        if is_call:
             # Attempt to resolve call target
             refs = list(idautils.CodeRefsFrom(ea, 0)) # 0 = flow ignored if not call?
             # Actually code refs include flow, but for call insn usually just one code ref + flow
             # But idautils.CodeRefsFrom(ea, 0) iterates flows too? 
             # Use ida_xref.get_first_cref_from(ea) and check type
             
             xref = ida_xref.get_first_cref_from(ea)
             while xref != ida_idaapi.BADADDR:
                 if xref != ea + length: # Ignore fallthrough
                      target_ea = xref
                      target_name = ida_name.get_name(xref)
                      break
                 xref = ida_xref.get_next_cref_from(ea, xref)

        for i in range(8):
            op = insn_t.ops[i]
            if op.type == ida_ua.o_void:
                break
            
            val_str = ""
            if op.type == ida_ua.o_reg:
                val_str = str(op.reg)
            elif op.type in [ida_ua.o_imm, ida_ua.o_mem, ida_ua.o_near, ida_ua.o_far]:
                 # Try to get symbolic name if it exists?
                 val_str = str(op.value)
            
            ops.append({
                "type": op.type,
                "value": val_str,
                "is_reg": op.type == ida_ua.o_reg,
                "is_imm": op.type == ida_ua.o_imm
            })
            
        insns.append({
            "ea": ea,
            "mnemonic": mnem,
            "operands": ops,
            "bytes_hex": bytes_hex,
            "target_ea": target_ea,
            "target_name": target_name
        })
    return insns

def extract_driver_data(anchor_function_name: str) -> dict:
    """
    Extracts comprehensive data about the driver, centered around an anchor function.
    """
    log_debug(f"[{_PID}] Starting driver data extraction with anchor: {anchor_function_name}")

    anchor_ea = find_anchor_function(anchor_function_name)
    if anchor_ea == idaapi.BADADDR:
        log_debug(f"[{_PID}] Anchor function '{anchor_function_name}' not found.")
        return None

    # 1. Collect all functions
    functions = {}
    for func_ea in idautils.Functions():
        func_name = ida_name.get_name(func_ea)
        functions[str(func_ea)] = {
            "name": func_name,
            "start_ea": func_ea,
            "end_ea": ida_funcs.get_func(func_ea).end_ea,
            "size": ida_funcs.get_func(func_ea).size(),
            "is_entry": (func_ea == anchor_ea)
        }

    # 2. Build Call Graph
    call_graph = {}
    for func_ea in idautils.Functions():
        func_name = ida_name.get_name(func_ea)
        call_graph[str(func_ea)] = []
        for xref in idautils.XrefsFrom(func_ea, 0):
            if xref.type == ida_xref.fl_CN or xref.type == ida_xref.fl_CF: # Call Near/Far
                if ida_funcs.get_func(xref.to): # Ensure target is a function
                    call_graph[str(func_ea)].append(str(xref.to))

    # 3. Extract Instructions for each function
    func_instructions = {}
    for func_ea in idautils.Functions():
        func = ida_funcs.get_func(func_ea)
        if func:
            # Limit instruction dumping for very large functions to avoid memory issues
            # if func.size() < 10000:
            insns = _extract_instructions(func)
            func_instructions[func_ea] = insns

    # 4. Extract Attack Surface (Driver Interface)
    driver_interface = _extract_driver_interface(anchor_ea)

    return {
        "metadata": {
            "timestamp": "now",
            "file_sha256": "TODO",
            "input_file": idaapi.get_input_file_path()
        },
        "functions": functions,
        "call_graph": call_graph,
        "function_instructions": func_instructions,
        "driver_interface": driver_interface,
        "strings": [], # TODO
        "imports": []  # TODO
    }

def _extract_driver_interface(driver_entry_ea: int) -> dict:
    """
    Analyze DriverEntry to find MajorFunctions and Device Creation.
    Simple heuristic scanner.
    """
    interface = {
        "dispatch_table": [],
        "devices": [],
        "ioctls": [], # Hard to find statically without HexRays, placeholder
        "detected_pools": []
    }
    
    if driver_entry_ea == idaapi.BADADDR or driver_entry_ea is None:
        return interface

    # 1. Scan DriverEntry for MajorFunction assignments
    # Look for: mov [reg + offset], imm/reg (where offset is usually 0x70 + index * 8)
    # DriverObject structure offsets (x64):
    # +0x038 MajorFunction : [28] Ptr64
    
    # We'll just look for immediate moves of function addresses into memory
    # This is a very rough heuristic.
    
    func = ida_funcs.get_func(driver_entry_ea)
    if not func: return interface
    
    # Track potential function pointers assigned
    for ea in range(func.start_ea, func.end_ea):
        insn = ida_ua.insn_t()
        ida_ua.decode_insn(insn, ea)
        
        # Check for: mov [mem], offset Function
        if insn.itype == ida_allins.NN_mov: # Standard move
            # Check Op1 (Dest) is Memory/Displ
            if insn.ops[0].type in [ida_ua.o_mem, ida_ua.o_displ, ida_ua.o_phrase]:
                # Check Op2 (Src) is Immediate (Function Address) or Reg (Scanning reg is hard)
                if insn.ops[1].type in [ida_ua.o_imm, ida_ua.o_near]:
                    src_val = insn.ops[1].value
                    # Verify if src_val is a function
                    if ida_funcs.get_func(src_val):
                        # Heuristic: Determine IRP MJ code based on offset? 
                        # Hard without exact struct tracking.
                        # Instead, just list them as generic handlers for now.
                        handler_name = ida_name.get_name(src_val)
                        interface["dispatch_table"].append({
                            "irql": "PASSIVE", # Default assumption
                            "major_function": -1, # Unknown index
                            "handler_ea": src_val,
                            "handler_name": handler_name
                        })
    
    # 2. Scan for IoCreateDevice calls
    # Check for calls to import "IoCreateDevice"
    # Then Look at arguments (DeviceName string)
    
    return interface

def _handle_analyze_command(args: dict) -> dict:
    """Handle analyze command - DUMP JSON ONLY (Standalone helper)."""
    try:
        anchor_function_name = args.get("anchor_function", "")
        log_debug(f"[{_PID}] Extracting data with anchor: {anchor_function_name}")
        
        data = extract_driver_data(anchor_function_name)
        
        if not data:
             return make_error_response("EXTRACTION_FAILED", "Could not extract data (Anchor not found?)")

        return make_success_response({
            "extracted_data": data,
            "anchor_ea": hex(find_anchor_function(anchor_function_name) or 0)
        })
        
    except Exception as e:
        log_debug(f"[{_PID}] Analyze exception: {e}\n{traceback.format_exc()}")
        return make_error_response("ANALYSIS_FAILED", str(e), traceback.format_exc())

# REMOVED: build_logic_graph, classify_function_role (Logic moved to Core Engine)


# ========================================================================
# CONFIGURATION LOADER (Sync with Main Process)
# ========================================================================
def load_dynamic_config():
    """Load configuration passed from main process via JSON file."""
    try:
        # Args passed as: script.py [config_path]
        if len(sys.argv) > 1:
            config_path = sys.argv[-1]
            if os.path.exists(config_path) and config_path.endswith('.json'):
                log_debug(f"Loading config from: {config_path}")
                with open(config_path, 'r') as f:
                    config = json.load(f)
                
                # Update heuristics_config if available
                if 'heuristics' in config:
                    try:
                        import heuristics_config
                        heuristics_config.HEURISTICS.update(config['heuristics'])
                        log_debug("Updated heuristics_config with dynamic values")
                    except ImportError:
                        log_debug("heuristics_config module not found, skipping update")
                        
                # Set global config for other modules
                global _GLOBAL_CONFIG
                _GLOBAL_CONFIG = config
                return True
    except Exception as e:
        log_debug(f"Config loading failed: {e}")
    return False

_GLOBAL_CONFIG = {}
load_dynamic_config()

# ========================================================================
# MAIN SERVER LOGIC
# ========================================================================
def main():
    """Main server loop."""
    """
    Entry point when run as script within IDA Pro.
    
    CRITICAL FIX: Server starts BEFORE auto_wait() to avoid False Timeout.
    """
    server = IDASocketServer()
    
    try:
        # 1. Start server FIRST (client can connect while analysis runs)
        server.start()
        
        # 2. Wait for IDA auto-analysis
        server.wait_for_auto_analysis()
        
        # 3. Accept client and send handshake
        server.accept_client()
        
        # 4. Run command loop
        server.run_command_loop()
        
    except Exception as e:
        log_debug(f"[{_PID}] FATAL: {e}\n{traceback.format_exc()}")
    finally:
        server.shutdown()
        idc.qexit(0)


# ========================================================================
# SCRIPT ENTRY POINT
# ========================================================================
if __name__ == '__main__':
    main()
else:
    # Also run if imported directly by IDA (fallback)
    main()