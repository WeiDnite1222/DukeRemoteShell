import os
import subprocess
import sys

PACKAGE_ROOT = os.path.abspath(os.path.dirname(__file__))
D_MANAGER_PATH = os.path.join(PACKAGE_ROOT, "main.py")
DUCK_SHELL_PATH = os.path.join(PACKAGE_ROOT, "dshell.py")
BUILD_PATH = os.path.join(PACKAGE_ROOT, "build")
REQUIREMENTS_PATH = os.path.join(PACKAGE_ROOT, "requirements.txt")

def main():
    py_executable = sys.executable
    os.makedirs(BUILD_PATH, exist_ok=True)

    try:
        import pip
    except ImportError:
        raise EnvironmentError("pip is not installed yet! Install it first before continuing.")

    if not os.path.exists(REQUIREMENTS_PATH):
        raise EnvironmentError("requirements.txt does not exist! Download it back from git first.")

    result = subprocess.run([
        py_executable,
        "-m",
        "pip",
        "install",
        "-r",
        str(REQUIREMENTS_PATH)
    ],
    check=True
    )

    if result.returncode != 0:
        raise Exception("An error occurred while installing requirements.txt.")

    if not os.path.exists(DUCK_SHELL_PATH):
        raise EnvironmentError("Duke shell does not exist! Download it back from git first.")

    if not os.path.exists(D_MANAGER_PATH):
        raise EnvironmentError("Duke shell does not exist! Download it back from git first.")

    result = subprocess.run(
        [
            py_executable,
            "-m",
            "nuitka",
            "--onefile",
            "--standalone",
            "--output-filename=dmanager",
            f"--output-dir={str(os.path.join(BUILD_PATH, "dmanager"))}",
            str(D_MANAGER_PATH)
        ],
        check=True
    )

    if result.returncode != 0:
        raise Exception("Unable to compile DManager!")

    result = subprocess.run(
        [
            py_executable,
            "-m",
            "nuitka",
            "--onefile",
            "--standalone",
            "--output-filename=dshell",
            f"--output-dir={str(os.path.join(BUILD_PATH, "dshell"))}",
            str(DUCK_SHELL_PATH)
        ]
    )

    if result.returncode != 0:
        raise Exception("Unable to compile DShell!")

    print("Done.")


if __name__ == "__main__":
    main()