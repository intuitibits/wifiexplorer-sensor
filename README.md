# Remote Sensor Setup

[WiFi Explorer Pro](https://www.adriangranados.com/apps/wifi-explorer) allows you to connect to a remote platform (e.g. Raspberry Pi) and perform a passive Wi-Fi scan using a capable Wi-Fi adapter. When a remote sensor is used, the scan results are sent back to WiFi Explorer Pro for its visualization.

**To use a platform as a remote sensor you will need a Linux-based computer with a Wi-Fi adapter capable of using monitor mode, and a Python script that enables the sensor functionality.**

## Installation

1. Download [wifiexplorer-sensor.py](../master/wifiexplorer-sensor.py) and copy the script to the Linux-based platform that will be used as a remote sensor. I recommend you place the script under ```/usr/local/bin```. Also, make sure it has executable permissions: 

```bash
sudo chmod +x /usr/local/bin/wifiexplorer-sensor.py
```

2. Install python3, python3-pip, scapy and tcpdump. If you're using a Debian-based platform you can type: 

```bash
sudo apt-get install python3 python3-pip tcpdump
sudo pip3 install scapy
```

3. Launch the script. For example, if _wlan0_ is the Wi-Fi adapter to be used, type: 

```bash
sudo nohup /usr/local/bin/wifiexplorer-sensor.py wlan0 > /tmp/wifiexplorer-sensor.log 2>&1 &
```

(**Optional**) You can make the script launch at startup by editing ```/etc/rc.local``` to include the line above. If your Wi-Fi adapter is other than _wlan0_, change it accordingly. Also, the line above must be included just before the line that says ```exit 0```, in case such line is present.

If you have a Debian-based system, you could also use the ```wifiexplorer-sensor``` startup script. Copy ```wifiexplorer-sensor``` to the target platform, then type the following to enable it:
  
```bash
sudo install -p -m 755 wifiexplorer-sensor /etc/init.d/wifiexplorer-sensor
sudo update-rc.d wifiexplorer-sensor defaults
sudo systemctl daemon-reload
```
  
Then, start the sensor by typing:
  
```bash
sudo service wifiexplorer-sensor start
```

## Use

Once the platform is ready, go to _WiFi Explorer Pro > Preferences > Sensors_ and click '+' to add the new sensor by entering its IP address. This address would be the wired (Ethernet) IP address unless you have a secondary Wi-Fi adapter you can use to connect to the sensor (the Wi-Fi adapter used for scanning will be switched to monitor mode while the scan is in progress!).

You can now go to the WiFi Explorer Pro toolbar and choose your remote sensor to start a scan.

