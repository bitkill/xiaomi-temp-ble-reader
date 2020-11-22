# Support the original author
Repo: [algirdasc/xiaomi-ble-mqtt](https://github.com/algirdasc/xiaomi-ble-mqtt)

<a href="https://www.buymeacoffee.com/Ua0JwY9" target="_blank"><img src="https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png" alt="Buy Me A Coffee" style="height: 41px !important;width: 174px !important;box-shadow: 0px 3px 2px 0px rgba(190, 190, 190, 0.5) !important;-webkit-box-shadow: 0px 3px 2px 0px rgba(190, 190, 190, 0.5) !important;" ></a>

# About
This is simple python script, which scans Xiaomi BLE Temperature and Humidity sensors and publishes their measurements to MQTT. 

# Installation

1. Install required packages:
    # needed for bluepy
    sudo apt install libglib2.0-dev
    
    # pip packages
    sudo pip3 install bluepy paho-mqtt

1. Clone code:

    git clone https://github.com/algirdasc/xiaomi-ble-mqtt.git
    cd xiaomi-ble-mqtt

1. Rename `mqtt.ini.sample` to `mqtt.ini` and configure MQTT broker by editing `mqtt.ini` file.

1. Scan for available Xiaomi BLE devices:
     ```bash
     sudo hcitool lescan
     ```
    Look for line which looks like this: 

    `4C:65:A8:D4:A3:1D MJ_HT_V1`
    
    Note: In case of an error running `lescan`, try restarting yout BLE device:
    ```
    hciconfig hci0 down
    hciconfig hci0 up
   ```

1. Rename `devices.ini.sample` to `devices.ini` and configure Xiaomi devices by editing `devices.ini` file:

    [room1]
    device_mac=4C:65:A8:XX:XX:XX
    topic=sensors/room1
    availability_topic=sensors/room1/availability
    average=3
    retain=1
    timeout=10
    
    [room2]
    device_mac=4C:65:A8:XX:XX:XX
    topic=sensors/room2
    
    etc...

MQTT Payload example:

    {"temperature": 25.7, "humidity": 42.0, "battery": 100}

