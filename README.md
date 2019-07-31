# ESP32_WiFi_Sniffer
Firmware that runs on top of FreeRTOS in order to sniff probe request packets. This is designed to work along with a complex desktop-side software for the analysis of captured data and its visualization. 

This firmware for the ESP32 does not work if it is not paired with the required software on the desktop side. Anyway I decided to release the source code because it can be useful to understand how to work with the ESP32.
Notice that the code also relies on a small modification of sntp.c file from Espressif (just a boolean flag added as global variable, which is set to 1 when NTP works correctly), which is not released here.
