# App Capture

Capture traffic from an android app and analyze it live with Wireshark

## Requirements

1. Android device connected with USB
2. [`PCAPdroid`](https://play.google.com/store/apps/details?id=com.emanuelef.remote_capture) app installed on your Android.
3. Make sure both your PC and Android are connected to the same network.

## Install
In `PCAPdroid`, go to `Settings > Control permissions > Generate API key`

## Run

Example command to run the script:

```bash
python app-capture.py -k <api_key> -a com.android.chrome
```
## Manual
```bash
usage: app-capture.py [-h] [-p COLLECTOR_PORT] [-v] [-w WRITE] [-s SERIAL] [-a TARGET_APP] [-k API_KEY] [-l LOGCAT_FILE]

Start PCAPdroid collector and capture.

options:
  -h, --help            show this help message and exit
  -p COLLECTOR_PORT, --collector-port COLLECTOR_PORT
                        Port for the collector to listen on.
  -v, --verbose         Enable verbose logging.
  -w WRITE, --write WRITE
                        File to write the PCAP data to (default: stdout).
  -s SERIAL, --serial SERIAL
                        ADB device serial number.
  -a TARGET_APP, --target-app TARGET_APP
                        Target app to capture data from (for example, com.android.chrome).
  -k API_KEY, --api-key API_KEY
                        API key for the PCAPdroid app.
  -l LOGCAT_FILE, --logcat-file LOGCAT_FILE
                        Logcat file name
```