"""
Harness Generator.

Generates C++ harness source code for fuzzing specific IOCTLs.
Targeting libFuzzer / generic executor style.
"""

ADDRESS_SANITIZER_HARNESS_TEMPLATE = """
#include <windows.h>
#include <stdint.h>
#include <stdio.h>

// Target Driver Configuration
#define TARGET_DEVICE "{device_name}"
#define TARGET_IOCTL 0x{ioctl_code:x}

HANDLE g_hDevice = INVALID_HANDLE_VALUE;

void InitDriver() {{
    if (g_hDevice == INVALID_HANDLE_VALUE) {{
        g_hDevice = CreateFileA(
            TARGET_DEVICE,
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL,
            OPEN_EXISTING,
            0,
            NULL
        );
        if (g_hDevice == INVALID_HANDLE_VALUE) {{
             printf("FATAL: Could not open device %s\\n", TARGET_DEVICE);
             // Optionally exit or ignore if using persistent mode
        }}
    }}
}}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {{
    InitDriver();
    
    if (g_hDevice == INVALID_HANDLE_VALUE) return 0;
    
    DWORD bytesReturned = 0;
    // Simple direct fuzzing of InputBuffer
    // Method/OutputBuffer handling depends on specific IOCTL type (BUFFERED/DIRECT)
    
    DeviceIoControl(
        g_hDevice,
        TARGET_IOCTL,
        (LPVOID)Data,
        (DWORD)Size,
        NULL, // Output Buffer (Optional: Fuzz output buffer size?)
        0,    // Output Buffer Size
        &bytesReturned,
        NULL
    );
    
    return 0;
}}
"""

class HarnessGenerator:
    """Produces C++ source code for fuzzing harnesses."""
    
    @staticmethod
    def generate_cpp_harness(device_name: str, ioctl_code: int) -> str:
        return ADDRESS_SANITIZER_HARNESS_TEMPLATE.format(
            device_name=device_name.replace("\\", "\\\\"),
            ioctl_code=ioctl_code
        )
