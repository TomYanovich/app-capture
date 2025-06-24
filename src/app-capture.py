import argparse
import fcntl
import os
import struct
import threading
import time

import platformdirs
from pathlib import Path
import shlex
from ppadb.client import Client as AdbClient
from scapy.all import *

APP_NAME = "app-capture"
API_KEY_FILENAME = "api_key.txt"
DEFAULT_LOGCAT_FILENAME = "logcat.log"


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


def create_tun(name='tun0', verbose: bool = False) -> int:
    link_show_cmd = shlex.join(["ip", "link", "show", name])
    if verbose:
        print(link_show_cmd)
    output1 = subprocess.run(link_show_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=True)
    if output1.returncode == 0:
        if verbose:
            print(f"TUN device {name} already exists.")
    else:
        # the device does not exist, create it
        add_device_cmd = shlex.join(["sudo", "ip", "tuntap", "add", "dev", name, "mode", "tun"])
        if verbose:
            print(add_device_cmd)
        out1 = subprocess.check_output(add_device_cmd, shell=True)
        if verbose:
            print(bcolors.OKBLUE + out1.decode() + bcolors.ENDC)
        else:
            print(out1.decode().strip())

    set_link_up_cmd = shlex.join(["sudo", "ip", "link", "set", name, "up"])
    if verbose:
        print(set_link_up_cmd)
    subprocess.run(set_link_up_cmd, shell=True)

    TUN_SET_IFF = 0x400454ca  # TUNSETIFF ioctl command
    IFF_TAP = 0x0002
    IFF_NO_PI = 0x1000
    tun = os.open('/dev/net/tun', os.O_RDWR | os.O_NONBLOCK)
    ifr = struct.pack('16sH', name.encode('utf-8'), IFF_TAP | IFF_NO_PI)
    fcntl.ioctl(tun, TUN_SET_IFF, ifr)
    return tun


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


def pidof(package: str, serial: str | None = None, verbose: bool = False) -> int:
    adb_client = AdbClient()
    device = adb_client.device(serial)
    pidof_cmd = "pidof " + package
    if verbose:
        print(pidof_cmd)
    output = device.shell(pidof_cmd)
    pid = int(output.strip())
    if verbose:
        print(bcolors.OKBLUE + output + bcolors.ENDC)
    return pid


def stream_logcat(outfile: str, serial: str | None = None, package: str | None = None, verbose: bool = False):
    def logcat_thread(filename: str, pid: int | None = None):
        adb_client = AdbClient()
        device = adb_client.device(serial)
        with open(filename, "w", encoding="utf-8") as f:
            logcat_cmd = f"logcat --pid {pid} -v time" if pid else "logcat -v time"
            if verbose:
                print(logcat_cmd)

            for line in device.shell(logcat_cmd):
                f.write(line)
                f.flush()

    pid = pidof(package=package, serial=serial, verbose=verbose)
    thread = threading.Thread(target=logcat_thread, args=(outfile, pid), daemon=True)
    thread.start()


def sniff(collector_port: int | None = 1234, verbose: bool = False, write: str = "-"):
    """
    Start a UDP socket to listen for PCAP packets from PCAPdroid and write them to a file or stdout.
    based on https://raw.githubusercontent.com/emanuele-f/PCAPdroid/refs/heads/master/tools/udp_receiver.py
    Args:
        collector_port: int, default 1234: Port for the collector to listen on.
        verbose: Enable verbose logging.
        write: str, default "-": File to write the PCAP data to (default: stdout). If "-", write to stdout.

    Returns:

    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", collector_port))
    BUFSIZE = 65535
    PCAP_HEADER_SIZE = 24

    # Standard PCAP header (struct pcap_hdr_s). Must be sent before any other PCAP record (struct pcaprec_hdr_s).
    # magic: 0xa1b2c3d4, v2.4
    PCAP_HDR_BYTES_PREFIX = bytes.fromhex("d4c3b2a1020004000000000000000000")
    pcapdroid_fd = create_tun("pcapdroid", verbose=args.verbose)

    def write_packets_to_fd():
        while True:
            data, addr = sock.recvfrom(BUFSIZE)
            is_pcap_header = (len(data) == PCAP_HEADER_SIZE) and (data.startswith(PCAP_HDR_BYTES_PREFIX))
            if is_pcap_header:
                continue
            os.write(pcapdroid_fd, b'\x00' * 6 + b'\x00' * 6 + b'\x08\x00' + bytes(
                data[16:]))  # Skip the first 16 bytes (PCAP header)

    fd_writer_thread = threading.Thread(target=write_packets_to_fd, daemon=True)
    fd_writer_thread.start()


def stop_capture(api_key: str, serial: str | None = None, verbose: bool = False) -> None:
    """
    API documentation: https://github.com/emanuele-f/PCAPdroid/blob/master/docs/app_api.md
    Args:
        verbose: Enable verbose logging.
        api_key: PCAPdroid API key.
        serial: adb device serial number, if multiple devices are connected.
    """
    adb_client = AdbClient()
    device = adb_client.device(serial)
    stop_capture_args = ["am", "start", "-e", "action", "stop", "-e", "api_key", api_key,
                         "-n", "com.emanuelef.remote_capture/.activities.CaptureCtrl"]

    stop_capture_cmd = shlex.join(stop_capture_args)
    if verbose:
        print(stop_capture_cmd)
    output = device.shell(stop_capture_cmd)
    if verbose:
        print(bcolors.OKBLUE + output + bcolors.ENDC)


def start_capture(api_key: str, collector_ip_address: str, target_app: str | None = None, collector_port: int = 1234,
                  serial: str | None = None, verbose: bool = False):
    """
    API codumentation: https://github.com/emanuele-f/PCAPdroid/blob/master/docs/app_api.md
    Args:
        verbose:
        collector_ip_address: IP address of the collector to send the captured data to.
        api_key: PCAPdroid API key.
        target_app: app package name to filter the capture (for example, com.android.chrome).
        collector_port: int, default 1234: Port for the collector to listen on.
        serial: adb device serial number, if multiple devices are connected.

    Returns:

    """
    adb_client = AdbClient()
    device = adb_client.device(serial)
    start_capture_args = ["am", "start", "-e", "action", "start", "-e", "api_key", api_key, "-e", "pcap_dump_mode",
                          "udp_exporter", "-e", "collector_ip_address", collector_ip_address, "-e", "collector_port",
                          str(collector_port)]
    if target_app:
        start_capture_args.extend(["-e", "app_filter", target_app])
    start_capture_args.extend(["-n", "com.emanuelef.remote_capture/.activities.CaptureCtrl"])

    start_capture_cmd = shlex.join(start_capture_args)
    if verbose:
        print(start_capture_cmd)
    output = device.shell(start_capture_cmd)
    if verbose:
        print(bcolors.OKBLUE + output + bcolors.ENDC)


if __name__ == '__main__':
    api_key = None
    api_key_file = Path(platformdirs.user_cache_dir(APP_NAME)) / API_KEY_FILENAME
    api_key_file.parent.mkdir(parents=True, exist_ok=True)
    if api_key_file.exists():
        with open(api_key_file, "r") as f:
            api_key = f.read().strip()

    adb_client = AdbClient()

    parser = argparse.ArgumentParser(description="Start PCAPdroid collector and capture.")
    parser.add_argument("-p", "--collector-port", type=int, default=1234, help="Port for the collector to listen on.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging.")
    parser.add_argument("-w", "--write", type=str, default="-",
                        help="File to write the PCAP data to (default: stdout).")
    parser.add_argument("-s", "--serial", type=str, choices=[dev.serial for dev in adb_client.devices()],
                        help="ADB device serial number.")
    parser.add_argument("-a", "--target-app", type=str,
                        help="Target app to capture data from (for example, com.android.chrome).")
    parser.add_argument("-k", "--api-key", type=str, required=True if api_key is None else False,
                        help="API key for the PCAPdroid app.")
    parser.add_argument("-l", "--logcat-file", type=str, default=DEFAULT_LOGCAT_FILENAME, help="Logcat file name")

    # Check that the package name is valid
    args = parser.parse_args()

    serial = None
    if not args.serial:
        serial = adb_client.devices()[0].serial

    device = adb_client.device(serial)
    if not device.is_installed(args.target_app):
        print(f"{bcolors.FAIL}package {args.target_app} is not installed.{bcolors.ENDC}")
        exit(1)

    # Cache api_key, or get from cache
    if args.api_key:
        with open(api_key_file, "w") as f:
            f.write(args.api_key)
            if args.verbose:
                print(f"API key saved to {api_key_file}")
    elif api_key:
        if args.verbose:
            print(f"Using API key from {api_key_file}")
        args.api_key = api_key

    try:
        # handle logcat streaming
        logcat_file = Path(platformdirs.user_log_dir(APP_NAME)) / args.logcat_file
        logcat_file.parent.mkdir(parents=True, exist_ok=True)
        if args.verbose:
            print(f"Logging {args.target_app} log to {logcat_file}")
        stream_logcat(serial=serial, package=args.target_app, verbose=args.verbose, outfile=str(logcat_file))

        # handle packet capture
        local_ip_address = get_local_ip_address()
        if args.verbose:
            print(f"Local IP address: {local_ip_address}")
            print("starting capture...")

        time.sleep(1)
        # handle local packet collector
        if args.verbose:
            print("starting collector...")
        sniff(collector_port=args.collector_port, verbose=args.verbose)

        time.sleep(1)
        start_capture(serial=serial, collector_ip_address=local_ip_address,
                      target_app=args.target_app, api_key=args.api_key, verbose=args.verbose)

        input("Press any key to terminate.")
    except KeyboardInterrupt:
        stop_capture(api_key=args.api_key, serial=serial)
    print("Done.")
