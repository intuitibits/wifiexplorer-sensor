# Remote Sensor Mode in WiFi Explorer Pro

[WiFi Explorer Pro](www.adriangranados.com/apps/wifiexplorer) allows you to connect to a remote platform (e.g. Raspberry Pi) and perform a passive Wi-Fi scan using a capable Wi-Fi adapter. When a remote sensor is used, the scan results are sent back to WiFi Explorer Pro for its visualization.

**To use a platform as a remote sensor you will need a Linux-based computer with a Wi-Fi adapter capable of using monitor mode, and a Python script that enables the sensor functionality.**

## Remote Sensor Setup

1. Download [wifiexplorer-sensor.py](../blob/master/wifiexplorer-sensor.py) and copy the script to the Linux-based platform that will be used as a remote sensor. I recommend you place the script under /usr/local/bin. Also, make sure it has executable permissions: 

```bash
sudo chmod +x /usr/local/bin/wifiexplorer-sensor.py
```

2. Install python, scapy and tcpdump. If you're using a Debian-based platform you can type: 

```bash
sudo apt-get install python scapy tcpdump
```

3. Launch the script. For example, if wlan0 is the Wi-Fi adapter to be used, type: 

```bash
sudo nohup /usr/local/bin/wifiexplorer-sensor.py wlan0 > /tmp/wifiexplorer-sensor.log 2>&1 &
```

4. (**Optional**) You can make the script launch at startup by editing /etc/rc.local to include the line above. If your Wi-Fi adapter is other than _wlan0_, change it accordingly. Also, the line above must be included just before the line that says ```exit 0```, in case such line is present.

Once the platform is ready, go to the WiFi Explorer Pro toolbar and choose _Add remote sensor…_ from the scan mode popup menu. Then, enter the IP address of the remote sensor. This address would be the wired (Ethernet) IP address unless you have a secondary Wi-Fi adapter you can use to connect to the sensor (the Wi-Fi adapter used for scanning will be switched to monitor mode while the scan is in progress!). 

You can manage sensors by going to _WiFi Explorer Pro > Preferences > Sensors_.
