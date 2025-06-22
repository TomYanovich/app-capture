import argparse
import getpass
import shlex
import socket
import subprocess
import time
from typing import List


def cleanup(running_processes: List[subprocess.Popen]) -> None:
    timeout_sec = 5
    for p in running_processes:
        p_sec = 0
        for second in range(timeout_sec):
            if p.poll() is None:
                time.sleep(1)
                p_sec += 1
        if p_sec >= timeout_sec:
            p.kill()
    print("Cleanup completed.")


def get_local_ip_address() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip = s.getsockname()[0]
    s.close()
    return ip


def check_if_port_is_open(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind(("", port))
            s.close()
            return True
        except OSError:
            return False


def check_ping_from_android(serial: str, host: str) -> bool:
    try:
        ping_cmd = ["adb"]
        if serial:
            ping_cmd.extend(["-s", serial])
        ping_cmd.extend(["shell", "ping", "-c", "1", host])
        print(shlex.join(ping_cmd))
        output = subprocess.check_output(shlex.join(ping_cmd), stderr=subprocess.DEVNULL, text=True, shell=True,
                                         timeout=5)
        return "1 received" in output
    except (subprocess.SubprocessError, RuntimeError) as e:
        return False


def start_collector(collector_port: int | None = 1234, verbose: bool = False, write: str = "-") -> List[
    subprocess.Popen]:
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

    return [collector_proc, wireshark_proc]  # Return the processes for cleanup


def stop_capture(api_key: str, serial: str | None = None) -> None:
    """
    API documentation: https://github.com/emanuele-f/PCAPdroid/blob/master/docs/app_api.md
    Args:
        api_key: PCAPdroid API key.
        serial: adb device serial number, if multiple devices are connected.
    """
    pcapdroid_cmd = ["adb"]
    if serial:
        pcapdroid_cmd.extend(["-s", serial])
    pcapdroid_cmd.extend(["shell", "am", "start", "-e", "action", "stop", "-e", "api_key", api_key,
                          "-n", "com.emanuelef.remote_capture/.activities.CaptureCtrl"])

    print(shlex.join(pcapdroid_cmd))
    subprocess.run(shlex.join(pcapdroid_cmd), shell=True, check=True)
    print("Capture stopped.")


def start_capture(api_key: str, collector_ip_address: str, target_app: str | None = None, collector_port: int = 1234,
                  serial: str | None = None) -> subprocess.Popen:
    """
    API codumentation: https://github.com/emanuele-f/PCAPdroid/blob/master/docs/app_api.md
    Args:
        collector_ip_address: IP address of the collector to send the captured data to.
        api_key: PCAPdroid API key.
        target_app: apacke name to filter the capture (for example, com.android.chrome).
        collector_port: int, default 1234: Port for the collector to listen on.
        serial: adb device serial number, if multiple devices are connected.

    Returns:

    """
    pcapdroid_cmd = ["adb"]
    if serial:
        pcapdroid_cmd.extend(["-s", serial])
    pcapdroid_cmd.extend(["shell", "am", "start", "-e", "action", "start", "-e", "api_key",
                          api_key, "-e", "pcap_dump_mode", "udp_exporter", "-e", "collector_ip_address",
                          local_ip_address,
                          "-e", "collector_port", str(collector_port)])
    if target_app:
        pcapdroid_cmd.extend(["-e", "app_filter", target_app])
    pcapdroid_cmd.extend(["-n", "com.emanuelef.remote_capture/.activities.CaptureCtrl"])

    time.sleep(2)
    print(shlex.join(pcapdroid_cmd))
    pcapdroid_proc = subprocess.Popen(shlex.join(pcapdroid_cmd), shell=True)
    return pcapdroid_proc


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

    processes = []
    try:
        local_ip_address = get_local_ip_address()
        print(f"Local IP address: {local_ip_address}")
        print("starting capture...")
        pcapdroid_proc = start_capture(serial=args.serial, collector_ip_address=local_ip_address, target_app=args.target_app, api_key=args.api_key)
        processes.append(pcapdroid_proc)

        print("starting collector...")
        is_port_open = check_if_port_is_open(args.collector_port)
        if is_port_open:

            collector_proc, wireshark_proc = start_collector()
            processes.extend([collector_proc, wireshark_proc])
        else:
            print(f"Port {args.collector_port} is already in use.")
            exit(1)

        input("Press any key to terminate.")
    except KeyboardInterrupt:
        cleanup(processes)
        stop_capture(api_key=args.api_key, serial=args.serial)


