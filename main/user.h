/*
	The purpose of this header file is to define all the details about the system to be configured
	for the specific ESP32 application (WiFi SSID, WiFi Password, PC IP address, NTP server IP address).
	The user should change these values according to his needs.
*/

#define NETWORK_SSID "ESP32_test"
#define NETWORK_PASSWORD "11235813"
#define IP_SOCKET "192.168.137.1" // this is the static ip address of the server (Windows hotspot)
#define PORT_SOCKET 1500 // this is the default port for the socket

// NTP-related settings. Notice that in the worst case scenario NTP requires (NTP_WAITING_TIME*NTP_RETRY_COUNT)/1000 seconds to complete.
#define NTP_SERVER "193.204.114.232" // ntp1.inrim.it
#define LOCAL_NTP_SERVER "192.168.137.1" // this is the ip of the local ntp server (if any)
#define FAKE_NTP_SERVER "127.0.0.1" // use localhost to redirect NTP request in order to force NTP with official NTP server to fail
#define NTP_WAITING_TIME 1000 // this is how much time (in milliseconds) we wait before checking if NTP worked
#define NTP_RETRY_COUNT 5 // this is the maximum number of times we retry checking for NTP (it's NOT the number of NTP queries)
#define CURRENT_YEAR 2019 // this one and the next one are used to check if NTP set the time correctly
#define BASE_YEAR 1900
#define MANUAL_SYNCH_ITERATIONS 20 // how many times the pc will send its time to the ESP32
#define CHANNEL_BEGIN 1 // first wifi channel to be used
#define CHANNEL_END 13 // last wifi channel to be used

#define VERBOSE // to print all messages from the board
#define HEAP_DEBUG // uncomment to enable heap debugging features (memory leaks may still be there in esp-idf components)
//#define DISABLE_NTP // uncomment this line to disable NTP (not the local one which remains active)