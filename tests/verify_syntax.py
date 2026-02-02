
import sys
import os
import compileall

project_root = r"d:\examinate\18\project"
print(f"Verifying syntax in {project_root}...")

try:
    # Compile python files to check for syntax errors
    if compileall.compile_dir(project_root, force=True, quiet=1):
        print("Syntax verification successful!")
        sys.exit(0)
    else:
        print("Syntax errors found.")
        sys.exit(1)
except Exception as e:
    print(f"Verification failed: {e}")
    sys.exit(1)
