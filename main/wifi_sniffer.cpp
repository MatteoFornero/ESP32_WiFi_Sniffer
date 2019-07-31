#include "wifi_sniffer.h"
using namespace std;

/* list to store data structures containing all important details about received packets.
   this must be a global variable because of the callback signature which does not accept 
   other parameters */
list<pkt_data> pkt_list; 

/* This function handles the real job that has to be done by the ESP32, notice that there is a neverending loop inside it because we want our system
   to be always active. In a real-world scenario this could be a problem if we use batteries to power-up the system, a possible solution could be to use
   the local time (i.e. from NTP server) to determine the moments when the system can be inactive (ex. from 7PM to 8.30AM), so
   in those moments we can enter the low power mode in order to save battery life. Otherwise the computer could tell the ESP32 to go in deep sleep for some time. */
void wifi_sniffer(char *esp_mac)
{
	uint8_t channel = 0; // channel to be scanned
	int current_socket = -1; // last socket used to communicate with the master, -1 for invalid socket
 	char input_buffer[6]; // buffer to read commands coming from the master
	bool skip_flag = false; // used to check if there was an error reading messages coming from the GUI
	bool synchronization_flag = false; // used to check if the board was able to get the time from NTP or PC
	
	/* LED Blinking variables and setup */
	TaskHandle_t led_task_handle = nullptr; // handle to the task for led blinking
	esp_timer_handle_t led_timer_handle = nullptr; // handle to the timer to stop led blinking
	const esp_timer_create_args_t led_timer_args = {
		&led_timer_callback, // function to call when timer expires
		(void*) &led_task_handle, // argument to pass to the callback, must be void*
		ESP_TIMER_TASK, // callback is called from timer task
		"led_timer", // timer name, must be a const char*
	};
	ESP_ERROR_CHECK(esp_timer_create(&led_timer_args, &led_timer_handle)); // create the timer to be used by the led blink function
	
	#ifdef HEAP_DEBUG
		size_t heap_begin = 0; // free heap size at the beginning of the loop
		size_t heap_end = 0; // free heap size at the end of the loop
	#endif
	
	for(;;){ // infinite loop
		
		ESP_LOGI(TAG, "ESP32 Probe Request Firmware v3.1 17-05-2019 11.10");
		
		#ifdef HEAP_DEBUG
			heap_begin = xPortGetFreeHeapSize();
		#endif
		
		ap_connect(); // connect to the access point
		current_socket = check_socket(current_socket); // check if there is a usable socket to communicate with the master, if not create a new one
		if(current_socket == -1){
			ESP_LOGE(TAG, "wifi_sniffer() - no valid socket to be used. skip to next iteration.");
			continue; // if current socket is not valid skip iteration
		}
		
		if(writeall(current_socket, esp_mac, MAC_LENGTH) == false){
			ESP_LOGE(TAG, "wifi_sniffer() - error sending MAC address. Retrying on a new socket...");
			close(current_socket); // write() failed so we close this socket and we will open a new one
			current_socket = -1; // make current socket invalid because we have closed it
			continue; // go to next iteration of the for loop (notice that ap_connect() won't to anything because we are already connected to the access point)
		}
		
		/* This internal loop is used to assist the configuration of the system performed in the GUI. If the MAC address is not among the allowed MAC addresses the pc will
		   send a "SLEEP" message and the ESP32 will enter into deep sleep status for a time specified by the DEEP_SLEEP_TIME constant defined by the user. Otherwise the ESP32
		   will toggle the onboard LED connected to GPIO_2 in order to help the user with the configuration of the system in the GUI, when the configuration is over the pc will
		   send the SYNCH message that allows the board to go on with the remaining operations. In case of an invalid command the socket is closed and the ESP32 goes on with
		   the next iteration of the external for loop. */
		for(;;){
			if(readall(current_socket, input_buffer, 6, 0) == false){ // read the command sent by the pc
				skip_flag = true; // here we use a flag because we have several sources for errors....in any case the flag will be tested later and appropriate actions will be performed
				ESP_LOGE(TAG, "wifi_sniffer() - error reading command from pc.");
				break;
			} else { // parse the command
				#ifdef VERBOSE
					input_buffer[5] = '\0'; // add null terminator to input buffer for safety reasons before printing it out (if command is correct this won't change it)
					ESP_LOGI(TAG, "wifi_sniffer() - Received command: %s", input_buffer);
				#endif
				if(strncmp(input_buffer, "BLINK\0", 6)==0){
					if(led_task_handle == nullptr){ // if this is the first time we receive blink we create the task, otherwise we don't do anything because the led task is already running
						ESP_ERROR_CHECK(esp_timer_start_once(led_timer_handle, BLINK_DURATION*1000000)); // start the timer to trigger blink stop (time duration is in microseconds)
						xTaskCreate(&led_task, "led_task", 1024, &led_task_handle, 5, &led_task_handle); // create task to use onboard led
						#ifdef VERBOSE
							ESP_LOGI(TAG, "wifi_sniffer() - LED task started.");
						#endif
					}
				} 
				else if(strncmp(input_buffer, "SYNCH\0", 6)==0){
					break; // we simply go ahead with the standard part of the system
				}
				else if(strncmp(input_buffer, "SLEEP\0", 6)==0){ // deep sleep
					#ifdef VERBOSE
						ESP_LOGI(TAG, "wifi_sniffer() - Attention: disabling WiFi before entering deep sleep status...");
					#endif
					esp_timer_stop(led_timer_handle); // stop the timer from running (no ESP_ERROR_CHECK because we don't know if the timer has ever started)
					esp_timer_delete(led_timer_handle); // delete the timer (no ESP_ERROR_CHECK because we don't know if the timer has ever started)
					if(led_task_handle != nullptr){ // stop immediately the blink
						vTaskDelete(led_task_handle); // delete led blinking task
						led_task_handle = nullptr; // set back the task handler to nullptr for safety reasons
						turn_off_led(); // this simply sets the onboard LED pin to 0 in order to turn it off
					}
					close(current_socket); // release resources before entering deep sleep
					xEventGroupClearBits(wifi_event_group, RECONNECT_BIT); // we don't want to reconnect
					esp_wifi_disconnect(); // we don't check for errors in next 3 calls because we only want to go in deep sleep
					esp_wifi_stop();
					esp_wifi_deinit();
					#ifdef VERBOSE
						ESP_LOGI(TAG, "wifi_sniffer() - Attention: now entering in deep sleep status...");
					#endif
					esp_deep_sleep(DEEP_SLEEP_TIME); // there is no proper return from this...the system will reboot
				} 
				else { // command not recognized
					skip_flag = true; // close and restart in case of problems
					ESP_LOGE(TAG, "wifi_sniffer() - invalid command from pc.");
					break;
				}
			}
		}
		
		// in case of any error in the internal for() loop
		if(skip_flag==true){
			skip_flag = false; // reset the flag
			close(current_socket);
			current_socket = -1; // make current socket invalid because we have closed it
			continue; // skip to next iteration
		}
		
		// run synchronization 
		synchronization_flag = synch(&channel, &current_socket, esp_mac); // if NTP fails and also manual synch fails the flag will be false
		close(current_socket); // close the socket (because either there was an error and we want to restart from the beginning or synch was successful and we will disconnect from the access point)
		current_socket = -1;
		if((synchronization_flag == false) || (channel < CHANNEL_BEGIN) || (channel > CHANNEL_END)){
			continue; // check if we got a valid channel to monitor or the synchronization failed....in this case skip to next iteration and restart from the beginning
		}
		
		xEventGroupClearBits(wifi_event_group, RECONNECT_BIT); // do not reconnect in case of disconnection (because we want to disconnect from AP)
		ESP_ERROR_CHECK(esp_wifi_disconnect()); // disconnect from wifi, otherwise packet capture would be done on the channel of the AP
		packet_monitor(channel); // this function handles the packet capture
		ap_connect(); // connect to the access point
		send_data(esp_mac, &current_socket); // send data to computer
		pkt_list.clear(); // free space used for list (linear cost with number of elements)
		
		#ifdef HEAP_DEBUG
			heap_end = xPortGetFreeHeapSize();
			ESP_LOGI(TAG, "HEAP MEMORY STATS -> start: %u | end: %u | net: %d", heap_begin, heap_end, (int)heap_end - (int)heap_begin);
			ESP_LOGI(TAG, "ABSOLUTE MINIMUM FREE HEAP SIZE: %u", xPortGetMinimumEverFreeHeapSize());
		#endif
	
	}	
}

// enable sniffer, wait 60 seconds, disable sniffer (in this time interval each probe request packet triggers the callback function)
void packet_monitor(uint8_t channel)
{
	#ifdef VERBOSE 
		ESP_LOGI(TAG, "packet_monitor() - starting to monitor probe requests on channel: %u", channel);
	#endif
	ESP_ERROR_CHECK(esp_wifi_set_promiscuous_rx_cb(&cb_func)); // register the callback function
	wifi_promiscuous_filter_t filter; // packet sniffing filters and parameters
	filter.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT; // filter management packets (probe requests are among them)
	ESP_ERROR_CHECK(esp_wifi_set_promiscuous_filter(&filter)); // set the filter
	ESP_ERROR_CHECK(esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE)); // set channel to be scanned, do not use a second channel
	ESP_ERROR_CHECK(esp_wifi_set_promiscuous(true)); // set the wifi interface into promiscuous mode
	vTaskDelay(SNIFFER_TIME / portTICK_PERIOD_MS); // wait 60 seconds...in the meantime the callback method will be triggered
	ESP_ERROR_CHECK(esp_wifi_set_promiscuous(false)); // disable promiscuous mode
	#ifdef VERBOSE
		ESP_LOGI(TAG, "packet_monitor - probe request monitoring completed, collected %d packets.", pkt_list.size());
	#endif
}

// callback function for probe request packets
void cb_func(void *buf, wifi_promiscuous_pkt_type_t type)
{
	uint64_t epoch = 0; // callback arrival time
	uint8_t pkt_type = 0; // packet type
	uint8_t pkt_subtype = 0; // packet subtype
	uint16_t seq_num = 0; // packet sequence number
	int8_t rssi = 0; // signal strength indicator
	uint16_t pkt_totlen = 0; // total length of packet (802.11 header + payload)
	uint16_t payload_len = 0; // length of payload
	uint32_t hash = 0; // digest of the packet
	char tmp_mac[MAC_LENGTH]; // temporary buffer to store source MAC address
	string source_mac; // packet's source mac address
	struct timeval current_time;
	uint8_t payload_offset = HEADERLEN; // this is the offset of the payload of the probe request within the packet (MAC header included)
	mac_header_t *header = nullptr; // pointer to the first byte of the captured packet, mac_header_t is a struct that mimics the header
	wifi_promiscuous_pkt_t *packet_captured = nullptr; // pointer to the packet captured by the ESP32 and passed to the callback
	char *packet_ptr = nullptr; // pointer to the first byte of the captured packet
	unique_ptr<char[]> payload_ptr = nullptr; // this is a smart pointer that points to the memory where we dump the payload of the probe request for further analysis
	
	// when callback is called get system time as soon as possible
	if(gettimeofday(&current_time, nullptr) != 0){
		return; // no reason to go on...the packet must have the right timestamp otherwise it is useless
	} else {
		epoch = ((uint64_t)current_time.tv_sec*1000)+((uint64_t)current_time.tv_usec/1000); // convert system time to epoch time
	}
	
	/* wifi_promiscuous_pkt_t is a type defined by Espressif that includes radio metadata header and a pointer to the packet itself 
	   including the MAC header. buf is the parameter, received by the callback, that points to the wifi_promiscuous_pkt_t. */
	packet_captured = (wifi_promiscuous_pkt_t *)buf;
	if(packet_captured == nullptr){
		return; // if pointer still null no reason to go on
	}
	
	/* wifi_promiscuous_pkt_t is a struct that includes some metadata so we store them into local variables. moreover it includes
	   also a pointer to the captured packet, we use it to store the informations about the mac header. */
	rssi = packet_captured->rx_ctrl.rssi; // this is the signal strength indicator
	pkt_totlen = packet_captured->rx_ctrl.sig_len - 4; // length of packet excluding FCS (which is 4 byte, that's why we remove them from sig_len)
	header = (mac_header_t *)packet_captured->payload; // retrieve the header (not all of it if packet was sent on 802.11n)
	if(header == nullptr){
		return;
	}
	
	/* mac_header_t allows to automatically parse the content of the header */
	pkt_type = header->type; // type of the packet (should be 00 -> management)
	pkt_subtype = header->subtype; // subtype of the packet (should be 0100 -> probe request)
	if(pkt_type!=0 || pkt_subtype!=4){
		return; // return if not a probe request packet
	}
	
	seq_num = header->seq_ctrl; // retrieve sequence number
	memset(tmp_mac, '0', MAC_LENGTH); // retrieve and convert source mac address
	int res = sprintf(tmp_mac, "%02x:%02x:%02x:%02x:%02x:%02x", header->source_addr[0], header->source_addr[1], header->source_addr[2], header->source_addr[3], header->source_addr[4], header->source_addr[5]);
	if(res != MAC_LENGTH-1){ // handle failure of sprintf setting the MAC to zero
		return; // no reason to go on if we can't label the packet with the sourca MAC address
	}
	try{
		source_mac.assign(tmp_mac);
	} catch(...) {
		return; // abort callback in case of any exception...we simply ignore this probe request
	}
	
	if(header->flags & 0x01){ // check if last bit of frame control is 1
		#ifdef VERBOSE
			ESP_LOGI(TAG, "Detected MAC frame with HT control field. Flags: %02x", header->flags);
		#endif
		payload_offset += 4; // HT control is 4 byte long so MAC header is 28 byte long and not 24
	}
	
	packet_ptr = (char*)packet_captured->payload; // this is a pointer to the first byte of the packet (MAC header and FCS included)
	payload_len = pkt_totlen - payload_offset; // this is the actual quantity of bytes we have in the payload of the probe request	
	
	try{
		payload_ptr = unique_ptr<char[]>(new char[payload_len]());
	}
	catch(...){
		payload_ptr = nullptr;
	}
	
	if(payload_ptr == nullptr){
		ESP_LOGE(TAG, "Callback failure...probably not enough heap memory.");
		return; // we simply give up the current callback
	} else {
		memcpy(payload_ptr.get(), packet_ptr+payload_offset, payload_len); // brutally dump the packet into RAM excluding header and FCS
		hash = djb2((unsigned char*)packet_ptr, pkt_totlen); // compute the hash of the packet
	}
	
	pkt_data pkt(source_mac, rssi, epoch, seq_num, hash, move(payload_ptr), payload_len); // create packet object 
	try{
		pkt_list.push_back(move(pkt)); // insert packet into list of packets to be sent to the computer
	} catch(...){
		return; // if insertion into list fails no problem...we return from the callback without memory leakage because the shared pointer will be destroyed, as the pkt_data object
	}
	#ifdef VERBOSE
		ESP_LOGI(TAG, "Source: %s | Timestamp: %llu | RSSI: %d | Seq.Numb: %u | Hash: %u", source_mac.c_str(), epoch, rssi, seq_num, hash);
	#endif
}

// this function sends collected data to the access point
void send_data(char *esp_mac, int *current_socket)
{
	int curr_socket = -1; // the socket that will be used to send data...when we send data we never have a usable socket because previously we were disconnected from the network
	uint16_t curr_bufdim = 0; // current dimension of the output buffer
	uint16_t pkt_dim = 0; // packet dimension
	uint16_t pkt_num = 0; // number of objects in the list 
	int tosend = 0; // packets to be sent to the computer
	char output_buffer[MAC_LENGTH+9]; // +2 for number of packets, +7 for "SENDING" message (SENDING + MAC + #packets captured)
	unique_ptr<char[]> data_buffer = nullptr; // buffer that will contain the data to be sent to the computer
	
	// create the socket because previously we were disconnected from AP
	curr_socket = create_socket();
	if(curr_socket < 0){
		ESP_LOGE(TAG, "send_data() - error creating socket");
		*current_socket = -1;
		return;
	} else {
		#ifdef VERBOSE
			ESP_LOGI(TAG, "send_data() - created socket number %d", curr_socket);
		#endif
	}
	
	/* first of all try to allocate memory for the output buffer...exceptions are handled simply forcing to 0 the packets to be sent */
	try{
		data_buffer = unique_ptr<char[]>(new char[DATA_BUFFER_DIM]()); 
	}
	catch(...){
		pkt_num = 0;
		data_buffer = nullptr;
	}
	
	// check again if data_buffer is valid
	if(data_buffer == nullptr){
		pkt_num = 0;
		ESP_LOGE(TAG, "send_data() - heap allocation failure.");
	} else {
		pkt_num = (uint16_t)pkt_list.size(); // number of packets collected by the ESP32
	}
	
	// fill the output buffer
	memset(output_buffer, '0', MAC_LENGTH+9);
	memcpy(output_buffer, "SENDING", 7);
	memcpy(output_buffer+7, esp_mac, MAC_LENGTH);
	serialize_uint((unsigned char*)&output_buffer[MAC_LENGTH+7], pkt_num, 2);
	
	if(writeall(curr_socket, output_buffer, MAC_LENGTH+9) == false){ // send total number of packets that are going to be sent
		close(curr_socket);
		*current_socket = -1;
		ESP_LOGE(TAG, "send_data() - error sending # of packets to pc");
		return;
	}
	
	/* if there's nothing to send return from the send function */
	if(pkt_num == 0){
		*current_socket = curr_socket; // copy back the socket (to be used later)
		return;
	}
	
	// start filling the buffer with the data
	memset(data_buffer.get(), '0', DATA_BUFFER_DIM); // clear the buffer	
	list<pkt_data>::iterator it = pkt_list.begin();
	tosend = pkt_num; // remaining objects to be serialized in the buffer
	while(tosend >= 0){ // keep going until there is something to send
		if(tosend > 0){
			pkt_dim = TL_LEN + METADATA_LEN + it->get_probe_req_payload_len(); // 6 bytes + 32 bytes + payload dump
		} else {
			pkt_dim = 0;
		}		
		if((curr_bufdim + pkt_dim > DATA_BUFFER_DIM) || tosend == 0){ // if data do not fit into the buffer or we reached the last element of the list we must send the data
			if(writeall(curr_socket, data_buffer.get(), curr_bufdim) == false){
				close(curr_socket);
				*current_socket = -1;
				ESP_LOGE(TAG, "send_data() - error sending data to pc.");
				return;
			}
			if(tosend > 0){ // there is still some data to send
				memset(data_buffer.get(), '0', DATA_BUFFER_DIM); // clear the buffer for next iterations
				curr_bufdim = 0; // we sent the data so the buffer is empty
			} else {
				tosend--; // this allows us to exit from the while (we enter here when we have sent all the data, i.e. tosend = 0)
			}
		} else {
			serialize_data(*it, data_buffer.get()+curr_bufdim); // put data inside the buffer (increment starting position)
			curr_bufdim += pkt_dim;
			tosend--;
			if(tosend > 0){
				it++; // go to the next element in the list (only if we are not at the last element of the list)
			}
		}
	}
	*current_socket = curr_socket; // copy back the socket (to be used later)
}

/*	synchronization of ESPs:
	1) try to get current time through NTP (double possibility: real NTP server or manually configured NTP server on local machine)
	2) if NTP didn't work try with manual synchronization
	3) wait for the GO signal from PC
	notes: the GO signal includes the channel to be used in promiscuous mode to sniff packets. if NTP or manual synch don't work the entire
	synch will fail. don't close socket here, it will be closed by the caller.
*/
bool synch(uint8_t *channel, int *current_socket, char *esp_mac)
{
	char input_buffer[4];
	bool ntp_success = false;
	bool manual_synch_success = false;
	int curr_socket = *current_socket;
	
	ntp_success = NTP_synch(); // try to get time from NTP server 
	
	if(ntp_success == false){ // if NTP didn't work
		manual_synch_success = manual_synch(curr_socket, ntp_success, esp_mac); // approximate manual clock synchronization with the pc
		if(manual_synch_success == false){
			ESP_LOGE(TAG, "synch() - error getting time from pc");
			return false;
		}
	} else {
		if(writeall(curr_socket, "NOSYNC\0", 7) == false){
			ESP_LOGE(TAG, "synch() - Error sending <no synch request> to the computer. Aborting synch.");
			return false;
		}
	}
	
	if(readall(curr_socket, input_buffer, 4, 0) == false){
		ESP_LOGE(TAG, "synch() - readall for GO failed");
		return false;
	} else if(strncmp(input_buffer, "GO\0", 3) != 0){
		ESP_LOGE(TAG, "synch() - error on GO buffer.");
		return false;
	}
	#ifdef VERBOSE
		ESP_LOGI(TAG, "synch() - received GO signal");
	#endif
	*channel = (uint8_t)input_buffer[3]; // last byte sent by pc is the channel to scan
	return true;
}