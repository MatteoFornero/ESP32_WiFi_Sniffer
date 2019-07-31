#include "wifi_sniffer.h"

/* GLOBAL VARIABLES */
const char* TAG = "@matteo"; // tag for ESP_LOGx function
EventGroupHandle_t wifi_event_group; // this is used to handle wifi events according to Espressif IDF APIs, an event group is simply a mask of bits to be periodically checked
int CONNECTED_BIT = BIT0;	// this is set when ESP32 connects to AP and reset when is disconnected
int RECONNECT_BIT = BIT1; // this is used to force reconnection when receiving STA_DISCONNECTED event*/

/* Disable name mangling for app_main() since ESP32 natively works with C but we are using C++. */
extern "C" {
	void app_main(void);
}

void app_main()
{
	wifi_event_group = xEventGroupCreate(); // bit mask for wifi events
	if(wifi_event_group == nullptr){
		ESP_LOGE(TAG, "app_main() - fatal error during system initialization. Reboot...");
		esp_restart(); // restart the system
	}
	char esp_mac[MAC_LENGTH]; // store esp32 mac address
	mysys_init(esp_mac); // initialize system components and wifi
	wifi_sniffer(esp_mac); // launch the real job, never returns
}

// system initialization function (one-time execution)
void mysys_init(char *esp_mac)
{
	uint8_t wint_mac[6]; // here we store the mac we get with the dedicated API
	memset(wint_mac, '0', 6); 
	ESP_ERROR_CHECK(nvs_flash_init()); // NVS (associative-like memory) initialization
	tcpip_adapter_init(); // tcp stack initialization
    ESP_ERROR_CHECK(esp_event_loop_init(event_handler, nullptr)); // event handler initialization
    wifi_init_config_t myconf = WIFI_INIT_CONFIG_DEFAULT(); // default wifi stack configuration parameters
    ESP_ERROR_CHECK(esp_wifi_init(&myconf)); // wifi stack initialization function with default configuration
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA)); // set the wifi interface to STA mode
    wifi_config_t wconf = { }; // set entire wifi_config_t variable to empty 
    memcpy(&wconf.sta.ssid, NETWORK_SSID, strlen(NETWORK_SSID));
    memcpy(&wconf.sta.password , NETWORK_PASSWORD, strlen(NETWORK_PASSWORD));
	wconf.sta.bssid_set = 0; // do not use bssid (no need to specify bssid because we don't use it)
	wconf.sta.channel = 0; // scan all channels
	ESP_ERROR_CHECK(esp_wifi_set_config(ESP_IF_WIFI_STA, &wconf)); // set wifi configuration
	ESP_ERROR_CHECK(esp_wifi_set_ps(WIFI_PS_NONE)); // disable power saving for wifi
	
	// setup country rules
	wifi_country_t wifi_country;
	memcpy(wifi_country.cc, "EU\0", 3);
	wifi_country.schan=1; 
	wifi_country.nchan=13; 
	wifi_country.policy=WIFI_COUNTRY_POLICY_AUTO;
	ESP_ERROR_CHECK(esp_wifi_set_country(&wifi_country));
	
	ESP_ERROR_CHECK(esp_wifi_get_mac(ESP_IF_WIFI_STA, wint_mac)); // retrieve MAC address of ESP32 with dedicated API	
	memset(esp_mac, '0', MAC_LENGTH); // clear buffer to store esp's mac address
	int res = sprintf(esp_mac, "%02x:%02x:%02x:%02x:%02x:%02x", wint_mac[0], wint_mac[1], wint_mac[2], wint_mac[3], wint_mac[4], wint_mac[5]); // generate string-like MAC address
	if(res != MAC_LENGTH-1){ // handle failure of sprintf setting the MAC to zero
		ESP_LOGE(TAG, "mysis_init() - fatal error retrieving the board's MAC address. Reboot...");
		esp_restart(); // reboot the system, we absolutely need the MAC address of the board otherwise it would be useless
	}
	
	ESP_ERROR_CHECK(esp_wifi_start()); // start wifi
}

// this function is the event handler that is called every time a new event is triggered by the system
esp_err_t event_handler(void *ctx, system_event_t *event)
{
	EventBits_t uxBits; // bitmask used to check if requested bit has changed
	switch (event->event_id) {
		case SYSTEM_EVENT_AP_PROBEREQRECVED: // this is never triggered by default (may be deprecated in future releases of esp-idf, added for completeness)
			ESP_LOGI(TAG, "Detected SYSTEM_EVENT_AP_PROBEREQRECVED");
			break;
		case SYSTEM_EVENT_STA_GOT_IP: // this means the ESP32 has got an IP from the AP so esp_wifi_connect() was successful
			ESP_LOGI(TAG, "Detected SYSTEM_EVENT_STA_GOT_IP");
			xEventGroupSetBits(wifi_event_group, CONNECTED_BIT); // set the connected bit to 1
			break;
		case SYSTEM_EVENT_STA_LOST_IP:
			ESP_LOGI(TAG, "Detected SYSTEM_EVENT_STA_LOST_IP");
			xEventGroupClearBits(wifi_event_group, CONNECTED_BIT); // reset the connected bit to 0
			uxBits = xEventGroupWaitBits(wifi_event_group, RECONNECT_BIT, pdFALSE, pdTRUE, 0); // do not wait for specific bit, return immediately its value
			if((uxBits & RECONNECT_BIT) != 0){ // if reconnect bit is set to 1 we try to reconnect
				ESP_ERROR_CHECK(esp_wifi_connect()); 
			}
			break;
		case SYSTEM_EVENT_STA_CONNECTED:
			ESP_LOGI(TAG, "Detected SYSTEM_EVENT_STA_CONNECTED");
			// we don't set the connected bit to 1 here because we want to wait for the DHCP to give us an IP address
			break;
		case SYSTEM_EVENT_STA_DISCONNECTED:
			ESP_LOGI(TAG, "Detected SYSTEM_EVENT_STA_DISCONNECTED");
			xEventGroupClearBits(wifi_event_group, CONNECTED_BIT); // reset the connected bit to 0
			uxBits = xEventGroupWaitBits(wifi_event_group, RECONNECT_BIT, pdFALSE, pdTRUE, 0); // do not wait for specific bit, return immediately its value
			if((uxBits & RECONNECT_BIT) != 0){ // if reconnect bit is set to 1 we try to reconnect
				ESP_ERROR_CHECK(esp_wifi_connect());
			}
			break; 
		case SYSTEM_EVENT_STA_START: // last 2 events added for completeness
			ESP_LOGI(TAG, "Detected SYSTEM_EVENT_STA_START");
			break;
		case SYSTEM_EVENT_STA_STOP:
			ESP_LOGI(TAG, "Detected SYSTEM_EVENT_STA_STOP");
			break;
		default:
			ESP_LOGI(TAG, "Detected unmapped event!");		
			break;
	}
    return ESP_OK;
}