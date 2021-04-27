import subprocess
from pathlib import Path


def main():
    """
    Creates a built in FTP server on IIS by running a PowerShell script
    """
    package_dir = Path(__file__).parent.absolute()
    script_path = str(package_dir / "create-server.ps1")
    cmd = ["PowerShell", "-File", script_path]
    p = subprocess.run(cmd, capture_output=True)
    if p.stderr:
        print("Couldn't create FTP server. The script must be ran as admin.")
    else:
        print("FTP server successfully created")


if __name__ == "__main__":
    main()