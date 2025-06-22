# App Capture

Capture traffic from an android app and analyze it live with Wireshark

## Requirements

1. Android device connected with USB
2. [`PCAPdroid`](https://play.google.com/store/apps/details?id=com.emanuelef.remote_capture) app installed on your
   Android.
3. [`adb`](https://developer.android.com/tools/adb) and [`Wireshark`](https://www.wireshark.org/) installed on your PC.
4. Make sure both your PC and Android are connected to the same network.

## Install

1. Run `setup.py`.
   ```bash
   python setup.py install
   ```
1. In `PCAPdroid`, go to `Settings > Control permissions > Generate API key`

## Run

Example command to run the script:

```bash
python app-capture.py -k <api_key> -a com.android.chrome
```