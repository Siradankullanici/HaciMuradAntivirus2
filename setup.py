import sys
from cx_Freeze import setup, Executable

# Use "Win32GUI" as the base for a Windows GUI application.
base = "Win32GUI" if sys.platform == "win32" else None

# Define build options, including additional packages and files to include.
build_exe_options = {
    "packages": [
        "os",
        "sys",
        "hashlib",
        "mimetypes",
        "requests",
        "time",
        "re",
        "PySide6.QtWidgets",
        "PySide6.QtCore",
        "PySide6.QtGui",
    ],
    "include_files": [
        ("assets/spinner.gif", "assets/spinner.gif"),
    ],
    "excludes": ["tkinter"],  # Exclude unnecessary packages to reduce package size.
}

# Define the executable, including the icon and UAC settings.
executables = [
    Executable(
        "antiviruscloud.py",  # Your application's entry point script.
        base=base,
        target_name="HydraDragonAntivirus.exe",  # Fixed the parameter name
        icon="assets/HydraDragonAV.ico",
        uac_admin=True,  # Request administrator privileges on startup.
    )
]

# Setup configuration.
setup(
    name="HydraDragonAntivirus",
    version="0.1.0",
    description="A PySide6 GUI application for file scanning (cloud analysis only)",
    options={"build_exe": build_exe_options},
    executables=executables,
)
