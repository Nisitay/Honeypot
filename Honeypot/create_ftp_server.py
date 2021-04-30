import subprocess
from pathlib import Path


def main():
    """
    Creates a built in FTP server on IIS by running a PowerShell script
    """
    script_path = Path("./create-server.ps1").absolute()
    cmd = ["PowerShell", "-File", script_path]
    p = subprocess.run(cmd, capture_output=True)
    if p.stderr:
        print("An error has occurred. Make sure the script is ran as Admin.")
    else:
        print("FTP server successfully created")


if __name__ == "__main__":
    main()