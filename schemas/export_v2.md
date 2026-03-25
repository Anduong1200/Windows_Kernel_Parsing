# Logic Flow Analysis Export Schema v2.0

This document defines the JSON structure produced by the disassembler exporter
and consumed by the FastDiff core engine. The schema is **disassembler-agnostic**.

> **Breaking change from v1**: `call_graph` now uses `List[CallSite]` with
> `callsite_ea` instead of `Map<Address, List<Address>>`. All new fields are
> required starting v2.

## Root Object

| Field | Type | Description |
|---|---|---|
| `metadata` | `ExportMetadata` | Binary and analysis run metadata |
| `functions` | `Map<str, FunctionInfo>` | All functions (key = decimal EA as string) |
| `call_graph` | `List[CallSite]` | Call graph edges with callsite resolution |
| `function_instructions` | `Map<str, List[Instruction]>` | Per-function instruction dump |
| `strings` | `List[StringEntry]` | Extracted strings with xrefs |
| `imports` | `List[ImportEntry]` | External imports |
| `exports` | `List[ExportEntry]` | Exported symbols |
| `driver_interface` | `DriverInterface` | Attack surface model |

## ExportMetadata

```json
{
  "schema_version": "2.0",
  "binary_sha256": "a1b2c3...",
  "timestamp": "2026-03-25T14:00:00Z",
  "tool": "IDA Pro 9.1",
  "input_file": "C:\\Drivers\\ndis.sys",
  "arch": "x64",
  "file_format": "PE"
}
```

## CallSite (NEW in v2)

```json
{
  "caller_ea": 5368713280,
  "callee_ea": 5368714240,
  "callsite_ea": 5368713310,
  "type": "direct",
  "target_name": "RtlInitUnicodeString"
}
```

## StringEntry (NEW in v2)

```json
{
  "ea": 5368720000,
  "value": "\\Device\\MyDriver",
  "encoding": "utf-16",
  "xref_funcs": [5368713280, 5368713400]
}
```

## ImportEntry (NEW in v2)

```json
{
  "ea": 5368730000,
  "name": "IoCreateDevice",
  "module": "ntoskrnl.exe",
  "ordinal": null
}
```

## ExportEntry (NEW in v2)

```json
{
  "ea": 5368713280,
  "name": "DriverEntry",
  "ordinal": 1
}
```

## FunctionInfo

```json
{
  "ea": 5368713280,
  "name": "DriverEntry",
  "start_ea": 5368713280,
  "end_ea": 5368713500,
  "size": 220,
  "is_import": false,
  "is_export": true,
  "demangled_name": null
}
```

## Instruction

```json
{
  "ea": 5368713280,
  "mnemonic": "mov",
  "operands": [
    { "type": 1, "value": "rax", "is_reg": true, "is_imm": false },
    { "type": 2, "value": "rbx", "is_reg": true, "is_imm": false }
  ],
  "bytes_hex": "4889C5",
  "target_ea": null,
  "target_name": null
}
```

## DriverInterface

```json
{
  "dispatch_table": [
    {
      "major_function": 14,
      "handler_ea": 5368714240,
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
      "code": 2236419,
      "method": "BUFFERED",
      "handler_ea": 5368714400,
      "input_size": 1024,
      "output_size": 0
    }
  ],
  "detected_pools": ["MyDr"]
}
```
