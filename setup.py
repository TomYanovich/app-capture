import os
import requests
import shlex
from shutil import which
import subprocess

UDP_RECEIVER_URL = "https://raw.githubusercontent.com/emanuele-f/PCAPdroid/refs/heads/master/tools/udp_receiver.py"

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def download_file(url: str, local_filename: str) -> None:
    with requests.get(url, stream=True) as r:
        r.raise_for_status()
        with open(local_filename, 'wb') as f:
            for chunk in r.iter_content(chunk_size=8192):
                f.write(chunk)

def main():
    udp_receiver_path = "./src/udp_receiver.py"
    if os.path.exists(udp_receiver_path):
        print("udp_receiver.py already exists. skipping download...")
    else:
        print("Downloading udp_receiver.py...")
        download_file(UDP_RECEIVER_URL, udp_receiver_path)
    print(f"{bcolors.OKGREEN}udp_receiver.py downloaded successfully.{bcolors.ENDC}")

    is_wireshark_installed = which("wireshark")
    if not is_wireshark_installed:
        print(f"{bcolors.FAIL}* Wireshark is not installed. Please install it to use this script.{bcolors.ENDC}\nRun:\n\tsudo apt install wireshark\n-----------------------------------------")
        exit(1)

    is_adb_installed = which("adb")
    if not is_adb_installed:
        print(f"{bcolors.FAIL}* ADB is not installed. Please install it to use this script.{bcolors.ENDC}\nRun:\n\tsudo add-apt-repository ppa:nilarimogard/webupd8\n\tsudo apt update\n\tsudo apt install android-tools-adb\n-----------------------------------------")
        exit(1)

    is_pcapdroid_installed = False
    check_pcapdroid_cmd = ["adb", "shell", "pm", "list", "package"]

    with subprocess.Popen(shlex.join(check_pcapdroid_cmd), shell=True, stdout=subprocess.PIPE, text=True) as p:
        for line in p.stdout:
            if line.strip() == "package:com.emanuelef.remote_capture":
                is_pcapdroid_installed = True

    if not is_pcapdroid_installed:
        print(f"{bcolors.FAIL}* PCAPdroid is not installed. Please install it.{bcolors.ENDC}")
        exit(1)

    print(f"{bcolors.OKGREEN}All dependencies are installed. You can now run the app-capture.py script.{bcolors.ENDC}")



if __name__ == '__main__':
    main()