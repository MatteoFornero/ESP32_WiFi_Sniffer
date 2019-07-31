#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include <string>
#include <list>
#include <memory>
#include "sys/time.h"
#include "esp_wifi.h"
#include "esp_event_loop.h"
#include "freertos/event_groups.h"
#include "freertos/FreeRTOS.h"
#include "nvs_flash.h"
#include "lwip/sockets.h"
#include "esp_log.h"
#include "lwip/apps/sntp.h"
#include "driver/gpio.h"
#include "freertos/task.h"
#include "esp_timer.h"

// user defined parameters
#include "user.h"

/* USEFUL CONSTANTS */
#define MAC_LENGTH 18 // length of the MAC address (i.e. da:a1:19:0b:3e:7f + 1 byte for '\0')
#define METADATA_LEN 32 // length of metadata to be sent to the computer (source MAC, timestamp, RSSI, hash...)
#define TL_LEN 6 // length of Type + Len fields in buffer to be sent to computer
#define HEADERLEN 24 // header length for 802.11b\g (non-HT) frames (802.11n frames have 4 more bytes in the header)
#define SNIFFER_TIME 60000 // value (in milliseconds) we wait before turning off sniffer mode and change channel
#define DATA_BUFFER_DIM 1400 // length of buffer we send each time to the computer (1400 because in general MTU is 1500 byte)
#define DEEP_SLEEP_TIME 28800000000 // microseconds (default is 8 hours) to stay in deep sleep (no problem for overflow, parameter is uint64_t)
#define BLINK_DURATION 5 // led blinking duration in seconds
#define FREQUENCY 3 // frequency of LED blinking

/* GLOBAL variables */
extern int CONNECTED_BIT;	// this is set when ESP32 connects to AP and reset when is disconnected
extern int RECONNECT_BIT; // this is used to force reconnection when receiving STA_DISCONNECTED event (not always active)
extern EventGroupHandle_t wifi_event_group; // group of bits to handle wifi events
extern const char* TAG; // tag for ESP_LOGx()

/* FUNCTION PROTOTYPES */
void packet_monitor(uint8_t); // handles packet monitoring
bool synch(uint8_t *channel, int *current_socket, char *esp_mac); // handles time synchronization with NTP or PC
void send_data(char *esp_mac, int *current_socket); // send data to computer
int create_socket(); // simply create a new socket
void cb_func(void *buffer, wifi_promiscuous_pkt_type_t type); // callback as defined by the API from Espressif
bool NTP_synch(); // get system time from NTP servers
bool manual_synch(int current_socket, bool ntp_success, char *esp_mac); // get system time with manual synchronization
uint32_t djb2(unsigned char *data, size_t len); // to compute the hash of the packet
bool wait_NTP(time_t *now, struct tm *timeinfo); // function called to wait for NTP to set the time
bool set_time(struct timeval *tv1); // used only when manual synchronization is required, it is used to set the system time
void mysys_init(char *esp_mac); // handles ESP32 initialization
esp_err_t event_handler(void *ctx, system_event_t *event); // handles events triggered by the WiFi driver
void wifi_sniffer(char *esp_mac); // handles the full working loop
void ap_connect(); // connect to the access point
int check_socket(int current_socket); // check if there's a valid socket, if not create a new one
void led_task(void *pvParameter); // for LED blinking
void turn_off_led(); // stop LED blinking from other task
void led_timer_callback(void *param); // triggered by timer to automatically stop LED blinking
bool readall(int socket, char *buffer, ssize_t end, int select_flag);
bool writeall(int socket, const char *buffer, ssize_t end);

/*  CLASS PACKET: this class defines an object that contains all the details we need about the probe request plus a smart pointer to a memory location 
    where we dumped the entire probe request payload in order to analyze its content (supported rates, vendor, capabilities etc...) */
class pkt_data
{
	private:
		std::string src_MAC; // source MAC address
		int8_t rssi; // signal strength
		uint64_t timestamp; // time since 1/1/1970	
		uint16_t seq_number; // sequence number of probe request
		uint32_t hash; // hash of the packet computed with DJB2 algorithm
		std::unique_ptr<char[]> probe_req_payload; // smart pointer to the probe request dump
		uint16_t probe_req_payload_len; // length of probe request dump
	public:
		pkt_data();
		pkt_data(std::string &MAC_source, int8_t signal_strength, uint64_t pkt_timestamp, uint16_t pkt_seq, uint32_t pkt_digest, std::unique_ptr<char[]> pkt_payload, uint16_t pkt_payload_len);
		std::string get_MAC();
		int8_t get_rssi();
		uint64_t get_timestamp();
		uint16_t get_seqnum();
		uint32_t get_hash();
		char* get_probe_req_payload();
		uint16_t get_probe_req_payload_len();
};

/*	this structure is used to grab the 802.11 header of the probe request packet which normally consists of 24 byte
	but can be 28 bytes long if it is a 802.11n packet and the "order" bit (LSB in frame control segment) is set to '1'.
	so with this structure we parse the entire header except for the optional "HT control" field, then we check into 
	the frame control bytes if 4 additional byte (HT control) are present and in that case we increase the offset to
	start reading the Element IDs associated to the probe request. */	
typedef struct {
	uint8_t version:2;  // 802.11 version (2 bit)
	uint8_t type:2; // type (management, control, data etc...) (2 bit)
	uint8_t subtype:4; // subtype (probe req, prob resp etc...) (4 bit)
	uint8_t flags; // these are remaining 8 bit of frame control element (we are interested in the last bit, order)
	uint16_t duration:16; // 16 bit
	uint8_t dest_addr[6]; // 6 byte
	uint8_t source_addr[6]; // 6 byte
	uint8_t bssid[6]; // 6 byte
	uint8_t frag_number:4; // fragment number, 4 bit
	uint16_t seq_ctrl:12; // sequence number of 802.11 frame (12 bits
} mac_header_t;

// functions to serialize packet info before sending through the socket
void serialize_data(pkt_data&, char *);
void serialize_uint(unsigned char *, uint64_t, uint8_t);
long deserialize_long(unsigned char *);