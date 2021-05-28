# Remote Sensor Setup [DEPRECATED]

**DEPRECATED:** Starting in WiFi Explorer Pro 3.2, a remote sensor doesn't longer need the `wifiexplorer-sensor` to enable the remote scanning function. For more information, see: [Connect to a Remote Sensor](https://intuitibits.com/help/wifiexplorerpro/#/topic-en.lproj-connect_remote_sensor).

---

[WiFi Explorer Pro](https://www.intuitibits.com/products/wifi-explorer-pro) allows you to connect to a remote platform (e.g. Raspberry Pi) and perform a passive Wi-Fi scan using a capable Wi-Fi adapter. When a remote sensor is used, the scan results are sent back to WiFi Explorer Pro for its visualization.

**To use a platform as a remote sensor you will need a Linux-based computer with a Wi-Fi adapter capable of using monitor mode, and a Python script that enables the sensor functionality.**

## Installation

1. Download [wifiexplorer-sensor](../master/wifiexplorer-sensor) and copy the script to the Linux-based platform that will be used as a remote sensor. We recommend you place the script under ```/usr/local/bin```. Also, make sure it has executable permissions: 

```bash
sudo chmod +x /usr/local/bin/wifiexplorer-sensor
```

2. Install python3 and python3-pip. If you're using a Debian-based platform you can type: 

```bash
sudo apt-get install python3 python3-pip
```

3. Install scapy:

```bash
sudo pip3 install scapy
```

## Starting the sensor

### Manual mode

If _wlan0_ is the Wi-Fi adapter to be used, type: 

```bash
sudo nohup /usr/local/bin/wifiexplorer-sensor wlan0 > /tmp/wifiexplorer-sensor.log 2>&1 &
```

### Automatic mode

You can make the script launch at startup by editing ```/etc/rc.local``` to include the line above. If your Wi-Fi adapter is other than _wlan0_, you need to change it accordingly. Also, the line above must be included just before the line that says ```exit 0```, in case such line is present.

However, we recommend using a startup script. Startup scripts for System V- and systemd-based initialization systems are provided under the ```scripts``` directory.

#### System V

Copy ```scripts/wifiexplorer-sensor``` to the target platform, then type the following to enable it:
  
```bash
sudo install -p -m 755 wifiexplorer-sensor /etc/init.d/wifiexplorer-sensor
sudo update-rc.d wifiexplorer-sensor defaults
sudo systemctl daemon-reload
```

You can start the sensor by typing:
  
```bash
sudo service wifiexplorer-sensor start
```

#### Systemd

Copy ```scripts/wifiexplorer-sensor.service``` to the target platform, then type the following to enable it:
  
```bash
sudo install -p -m 644 wifiexplorer-sensor.service /lib/systemd/system/wifiexplorer-sensor.service
sudo systemctl enable wifiexplorer-sensor.service
```

You can start the sensor by typing:
  
```bash
sudo systemctl start wifiexplorer-sensor
```

## Use

Once the platform is ready, go to _WiFi Explorer Pro > Preferences > Sensors_ and click '+' to add the new sensor by entering its IP address. This address would be the wired (Ethernet) IP address unless you have a secondary Wi-Fi adapter you can use to connect to the sensor (the Wi-Fi adapter used for scanning will be switched to monitor mode while the scan is in progress!).

You can now go to the WiFi Explorer Pro toolbar and choose your remote sensor to start a scan.
