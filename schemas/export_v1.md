# Logic Flow Analysis Export Schema v1.0

This document defines the JSON structure exported by the IDAPython script and consumed by the Core Engine. This ensures the Core Engine is decoupled from the specific disassembler (IDA, Ghidra, etc.).

## Root Object (`DriverAnalysisExport`)

| Field | Type | Description |
|---|---|---|
| `metadata` | Object | Meta-information about the analysis run. |
| `functions` | Map<Address, Function> | All functions found in the binary. |
| `call_graph` | List[Edge] | Call graph edges (Caller -> Callee). |
| `function_instructions` | Map<Address, List[Instruction]> | Detailed instruction dump for key functions. |
| `driver_interface` | Object | (New in v3.1) Extracted Attack Surface / Driver Interface model. |
| `strings` | List[String] | Strings found in the binary. |
| `imports` | List[Import] | External imports. |

## Metadata

```json
{
  "timestamp": "ISO8601 String",
  "tool": "IDA Pro 7.x",
  "export_version": "1.0",
  "binary_sha256": "Hex String"
}
```

## Function Object

```json
{
  "ea": 123456,            // Integer (Decimal key in JSON map usually stringified)
  "name": "DriverEntry",
  "start_ea": 123456,
  "end_ea": 123500,
  "size": 44,
  "is_import": false,
  "is_export": true
}
```

## Call Graph Edge

```json
{
  "caller_ea": 123456,
  "callee_ea": 123600,
  "type": "direct" // "direct", "indirect", "callback"
}
```

## Instruction Object

Used for fuzzy hashing and semantic analysis.

```json
{
  "ea": 123456,
  "mnemonic": "mov",
  "bytes_hex": "4889C5",
  "operands": [
    { "type": 1, "value": "rax", "is_reg": true },
    { "type": 2, "value": "rbx", "is_reg": true }
  ],
  "target_ea": 123999,      // Resolved target address (for calls/jumps)
  "target_name": "RtlInitUnicodeString" // Resolved symbol name
}
```

## Driver Interface (Attack Surface)

```json
{
  "dispatch_table": [
    {
      "major_function": 14, // IRP_MJ_DEVICE_CONTROL
      "handler_ea": 123600,
      "handler_name": "DispatchDeviceControl",
      "irql": "PASSIVE"
    }
  ],
  "devices": [
    {
      "name": "\\Device\\MyDriver",
      "symlink": "\\DosDevices\\MyDriver",
      "device_type": 34,
      "characteristics": 0
    }
  ],
  "ioctls": [
    {
      "code": 2236419, // 0x222003
      "method": "BUFFERED",
      "handler_ea": 123700,
      "input_size": 1024,
      "output_size": 0
    }
  ]
}
```
