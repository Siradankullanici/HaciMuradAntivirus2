import sys
import os
from cx_Freeze import setup, Executable

# Paths to Tcl/Tk
tcl_dir = r"C:\Belgeler ve Ayarlar\Yönetici\Masaüstü\python-3.5.0-winxp\python35\Lib\tcl8.6"
tk_dir = r"C:\Belgeler ve Ayarlar\Yönetici\Masaüstü\python-3.5.0-winxp\python35\Lib\tk8.6"

os.environ["TCL_LIBRARY"] = tcl_dir
os.environ["TK_LIBRARY"] = tk_dir

# Use "Win32GUI" as the base for a Windows GUI application.
base = "Win32GUI" if sys.platform == "win32" else None

# Dynamically locate python35.dll (assumes it resides in sys.exec_prefix)
python_dll = os.path.join(sys.exec_prefix, "python35.dll")
include_files = [
    (tcl_dir, "tcl"),
    (tk_dir, "tk"),
]

# Add python35.dll if it exists.
if os.path.exists(python_dll):
    include_files.append(python_dll)
else:
    print("Warning: python35.dll not found at", python_dll)

# Define build options.
build_exe_options = {
    "packages": [
        "os",
        "sys",
        "hashlib",
        "mimetypes",
        "requests",
        "time",
        "re",
        "tkinter",
    ],
    "include_files": include_files,
}

# Define the executable.
executables = [
    Executable(
        "antiviruscloudreactos.py",
        base=base,
    )
]

# Setup configuration.
setup(
    name="HaciMuradAntivirus",
    version="0.1.0",
    description="A cloud-based antivirus",
    options={"build_exe": build_exe_options},
    executables=executables,
)
