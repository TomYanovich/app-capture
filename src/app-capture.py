import argparse
import getpass
import shlex
import socket
import subprocess
import time


def get_local_ip_address() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip = s.getsockname()[0]
    s.close()
    return ip


def start_collector(collector_port: int | None = 1234, verbose: bool = False, write: str = "-"):
    arguments = ["python", "udp_receiver.py"]
    if collector_port and collector_port != 1234:
        arguments.extend(["-p", str(collector_port)])
    if verbose:
        arguments.append("-v")
    if write and write != "-":
        arguments.extend(["-w", write])

    collector_cmd = shlex.join(arguments)
    print(collector_cmd)
    collector_proc = subprocess.Popen(collector_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True,
                                      text=True)

    wireshark_cmd = shlex.join(["sudo", "wireshark", "-k", "-i", "-"])
    print(wireshark_cmd)
    with subprocess.Popen(wireshark_cmd, stdin=collector_proc.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          shell=True) as wireshark_proc:
        password = getpass.getpass()
        stdout, stderr = wireshark_proc.communicate(input=password.encode())
        if wireshark_proc.returncode == 0:
            print("Wireshark started successfully.")
        else:
            print(f"Error starting Wireshark: {stderr.decode()}")
            raise RuntimeError("Failed to start Wireshark.")


def start_capture(api_key: str, target_app: str | None = None, collector_port: int = 1234, serial: str | None = None):
    collector_ip_address = get_local_ip_address()
    arguments = ["adb"]
    if serial:
        arguments.extend(["-s", serial])
    arguments.extend(["shell", "am", "start", "-e", "action", "start", "-e", "api_key",
                      api_key, "-e", "pcap_dump_mode", "udp_exporter", "-e", "collector_ip_address",
                      collector_ip_address,
                      "-e", "collector_port", str(collector_port)])
    if target_app:
        arguments.extend(["-e", "app_filter", target_app])
    arguments.extend(["-n", "com.emanuelef.remote_capture/.activities.CaptureCtrl"])

    time.sleep(2)
    subprocess.Popen(shlex.join(arguments), shell=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Start PCAPdroid collector and capture.")
    parser.add_argument("-p", "--collector-port", type=int, default=1234, help="Port for the collector to listen on.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging.")
    parser.add_argument("-w", "--write", type=str, default="-",
                        help="File to write the PCAP data to (default: stdout).")
    parser.add_argument("-s", "--serial", type=str, help="ADB device serial number.")
    parser.add_argument("-a", "--target-app", type=str,
                        help="Target app to capture data from (for example, com.android.chrome).")
    parser.add_argument("-k", "--api-key", type=str, required=True, help="API key for the PCAPdroid app.")

    args = parser.parse_args()

    print("starting collector...")
    start_collector()

    print("starting capture...")
    start_capture(serial=args.serial, target_app=args.target_app, api_key=args.api_key)
    input("Press any key to terminate.")
