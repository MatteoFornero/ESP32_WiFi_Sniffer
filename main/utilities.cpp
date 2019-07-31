#include "wifi_sniffer.h"
using namespace std;

int SNTP_flag = 0; // global variable used in sntp.c to signal that NTP was successful

/*  Function to synch the ESP32 with a NTP server. Behavior:
	1) try to synch with a real NTP server
	2) if (1) fails try to synch with a local NTP server
	3) if (2) fails return false and the ESP32 will try with manual synchronization */
bool NTP_synch()
{
	time_t current_time;
	struct tm time_info;
	ip_addr_t ip_addr;
	
	sntp_setoperatingmode(SNTP_OPMODE_POLL); // initialize SNTP
	if(sntp_getoperatingmode() != SNTP_OPMODE_POLL){
		ESP_LOGE(TAG, "NTP_synch() - Error setting SNTP operating mode.");
		return false;
	}
	
	#ifdef DISABLE_NTP // for debugging purpose when we don't want to use NTP
		if(inet_pton(AF_INET, FAKE_NTP_SERVER, &ip_addr) != 1){
			ESP_LOGE(TAG, "NTP_synch() - Error converting IP address of NTP server.");
			return false;
		}
	#else // we want to use NTP 
		if(inet_pton(AF_INET, NTP_SERVER, &ip_addr) != 1){
			ESP_LOGE(TAG, "NTP_synch() - Error converting IP address of NTP server.");
			return false;
		}
	#endif
	
	sntp_setserver(0, &ip_addr); // set the NTP server we want to use
	sntp_init(); // enable SNTP
	#ifdef VERBOSE
		ESP_LOGI(TAG, "Waiting for official NTP server to set the time...");
	#endif
	
	if(wait_NTP(&current_time, &time_info) == false){
		ESP_LOGE(TAG, "NTP_synch() - Error getting current system time.");
		sntp_stop();
		return false;
	}	
	
	if(time_info.tm_year < (CURRENT_YEAR - BASE_YEAR) || SNTP_flag==0){ // if official NTP fails try with local NTP
		ESP_LOGE(TAG, "NTP_synch() - Official NTP failed. Trying with local NTP server...");
		if(inet_pton(AF_INET, LOCAL_NTP_SERVER, &ip_addr) != 1){
			ESP_LOGE(TAG, "NTP_synch() - Error converting IP address of NTP server.");
			sntp_stop(); 
			return false;
		}
		sntp_setserver(0, &ip_addr); // change server to local NTP
		if(wait_NTP(&current_time, &time_info) == false){
			ESP_LOGE(TAG, "NTP_synch() - Error getting current system time.");
			sntp_stop();
			return false;
		}
	}
	
	sntp_stop(); // disable SNTP because we are done
	if(time(&current_time) == (time_t)-1){ // read current time
		ESP_LOGE(TAG, "NTP_synch() - Error getting current system time.");
		return false;
	}
	if(localtime_r(&current_time, &time_info) == nullptr){
		ESP_LOGE(TAG, "NTP_synch() - Error getting current system time.");
		return false;
	}
	if(time_info.tm_year < (CURRENT_YEAR - BASE_YEAR) || SNTP_flag==0){
		ESP_LOGE(TAG, "NTP_synch() - Impossible to set the system time with NTP. ESP32 will try with manual synchronization...");
		SNTP_flag = 0; // reset the SNTP flag for the next iteration (should not be necessary here but just in case...)
		return false;
	} else {
		SNTP_flag = 0; // reset the SNTP flag for the next iteration
		#ifdef VERBOSE
			ESP_LOGI(TAG, "NTP set time correctly.");
		#endif
		return true;
	}
}

/* This is used only to save code...we simply wait some time for NTP to set the current time.
   This function always returns true unless there's an error in some sub-functions. In particular
   we return true even when NTP was not successful because the caller will check NTP status. */
bool wait_NTP(time_t *current_time, struct tm *time_info)
{
	uint8_t check = 0; // number of times we try to get time from NTP
	if(time(current_time) == (time_t)(-1)){ // read current time
		return false;
	}
	if(localtime_r(current_time, time_info) == nullptr){
		return false;
	}
	while((time_info->tm_year < (CURRENT_YEAR - BASE_YEAR) || SNTP_flag==0) && check < NTP_RETRY_COUNT){ // NTP_RETRY_COUNT is not the number of times we query the NTP server
		vTaskDelay(NTP_WAITING_TIME / portTICK_PERIOD_MS); // give some time to NTP...
		if(time(current_time)== (time_t)(-1)){ // read current time
			return false;
		}
		if(localtime_r(current_time, time_info) == nullptr){
			return false;
		}	
		check++;
	}
	return true;
}

/* Function to perform manual time synchronization with pc. */
bool manual_synch(int curr_socket, bool ntp_success, char *esp_mac)
{
	char input_buffer[8]; 
	ssize_t ret_value = 0;
	uint8_t i = 0;
	struct timeval input_check, input_time, current_time;
	fd_set rdfd;
	
	if(writeall(curr_socket, "SYNREQ\0", 7) == false){ // tell pc we want the current time
		ESP_LOGE(TAG, "manual_synch() - Error requesting manual synchronization to computer. Aborting manual synchronization.");
		return false;
	}
	
	input_check.tv_sec = 5; input_check.tv_usec = 0; // for the select
	for(i = 0; i < MANUAL_SYNCH_ITERATIONS; i++){
		FD_ZERO(&rdfd); FD_SET(curr_socket, &rdfd); 
		ret_value = select(curr_socket+1, &rdfd, nullptr, nullptr, &input_check); // wait until there's something to read or timeout expires
		if(ret_value==-1 || !FD_ISSET(curr_socket, &rdfd)){ // select error or timeout expired
			ESP_LOGE(TAG, "manual_synch() -  timeout expired waiting for timestamp from pc. Aborting manual synchronization.");
			return false;
		}
		// read the time (milliseconds from 1/1/1970)*/
		if(readall(curr_socket, input_buffer, 8, 1) == false){
			ESP_LOGE(TAG, "manual_synch() - error reading time sent by computer. Aborting manual synchronization.");
			return false;
		}
		
		if(i!=0){ // if this is not the first iteration of the loop get the current time as soon as possible in order to compare it later to the time we received
			if(gettimeofday(&current_time, nullptr) == -1){
				ESP_LOGE(TAG, "manual_synch() - error on gettimeofday(). Aborting manual synchronization.");
				return false;
			}
		}
		
		if(i!=0){ // if this is not the first iteration we must check if the time we just got is more precise than the current time
			input_time.tv_sec = deserialize_long((unsigned char*)input_buffer); // deserialize the timestamp sent by computer (first 4 bytes are seconds, last 4 bytes are microseconds)
			input_time.tv_usec = deserialize_long((unsigned char*)(input_buffer+4));
			// if the time received by the pc is "in the future" it means that the delay decreased and we set the time again
			if((input_time.tv_sec > current_time.tv_sec) || ((input_time.tv_sec == current_time.tv_sec) && (input_time.tv_usec > current_time.tv_usec))){ 
				if(set_time(&input_time) == false){
					ESP_LOGE(TAG, "manual_synch() - error setting time sent by computer. Aborting manual synchronization.");
					return false;
				}
			}
		} else {
			/* Notice that the time is always set at the first iteration. We could keep the time set in a previous window (i.e. one minute earlier) if the current manual synchronization fails
			   but the "old time" could be inaccurate so we act like we don't have the clock set at all. */
			if(set_time(&input_time) == false){
				ESP_LOGE(TAG, "manual_synch() - error setting time sent by computer. Aborting manual synchronization.");
				return false;
			}
		}
	}
	
	return true; // everything worked well
}

/* function used only when manual synchronization is required, it is used to set the system time */
bool set_time(struct timeval *new_time)
{
	if(settimeofday(new_time, nullptr) == -1){
		ESP_LOGE(TAG, "set_time() - error on settimeofday(). Aborting manual synchronization.");
		return false;
	}
	#ifdef VERBOSE
		uint64_t epoch = 0;
		if(gettimeofday(new_time, nullptr) == -1){
			ESP_LOGE(TAG, "set_time() - error on gettimeofday(). Aborting manual sync.");
			return false;
		}
		epoch = ((uint64_t)new_time->tv_sec*1000)+((uint64_t)new_time->tv_usec/1000);
		ESP_LOGI(TAG, "Time set to: %llu", epoch);
	#endif
	return true;
}

// create a socket
int create_socket()
{
	int curr_socket = -1; // the socket to be created
	struct sockaddr_in pc_addr;
	pc_addr.sin_family = AF_INET;
	pc_addr.sin_port = htons(PORT_SOCKET);
	int ret_value = inet_pton(AF_INET, IP_SOCKET, &(pc_addr.sin_addr));
	if(ret_value != 1){ // inet_pton returns 1 upon success
		return -1;
	} else {
		curr_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if(curr_socket < 0){ // this means error
			return -1;
		} else {
			if(connect(curr_socket, (struct sockaddr*) &pc_addr, sizeof(pc_addr)) != 0){ // 0 returned upon success
				close(curr_socket);
				return -1;
			} else {
				return curr_socket;
			}
		}
	}
}

// check if there is a valid socket to be used in communications with the pc
int check_socket(int current_socket)
{
	ssize_t ret_value = 0;
	char buffer[6];
	struct timeval tv; tv.tv_sec = 10; tv.tv_usec = 0;
	fd_set rdfd;
	bool sock_alive = false;
	
	if(current_socket != -1){ // current socket could still be valid
		if(writeall(current_socket, "ALIVE\0", 6) == true){ // send alive to pc
			FD_ZERO(&rdfd); FD_SET(current_socket, &rdfd); 
			ret_value = select(current_socket+1, &rdfd, nullptr, nullptr, &tv);
			if(ret_value==-1 || !FD_ISSET(current_socket, &rdfd)){ // select error or timeout expired
				#ifdef VERBOSE
					ESP_LOGI(TAG, "check_socket() - select timeout");
				#endif
			} else {
				if(readall(current_socket, buffer, 6, 1) == true){
					if(strncmp(buffer, "ALIVE\0", 6)==0){ // read alive sent by pc
						sock_alive = true;
					}	
				}
			}
		}
	}
	
	if(current_socket == -1 || sock_alive == false){ // this means we were not able to reuse the previous socket
		close(current_socket); // close current socket (just to avoid leaving a dangling socket around...maybe this socket is not even a valid file descriptor anymore)
		current_socket = create_socket(); // create a new socket
		if(current_socket < 0){
			ESP_LOGE(TAG, "check_socket() - error creating socket");
			return -1; // return an invalid socket descriptor if there was any problem
		} else {
			#ifdef VERBOSE
				ESP_LOGI(TAG, "check_socket() - new socket created");
			#endif
			return current_socket;
		}
	} else {
		#ifdef VERBOSE
			ESP_LOGI(TAG, "check_socket() - old socket recovered");
		#endif
		return current_socket;
	}
}

/* this is used to handle also partial write. if the pc on the other side reads too slowly an error is returned. */
bool writeall(int socket, const char *buffer, ssize_t end)
{
	ssize_t res;
	ssize_t start = 0;
	struct timeval output_check;
	fd_set wrfd;
	output_check.tv_sec = 2; output_check.tv_usec = 0; // for the select
	while(start < end){
		FD_ZERO(&wrfd); FD_SET(socket, &wrfd); 
		res = select(socket+1, nullptr, &wrfd, nullptr, &output_check); // wait until there's space on TCP output buffer
		if(res==-1 || !FD_ISSET(socket, &wrfd)){ // select error or timeout expired
			ESP_LOGE(TAG, "writeall() - select timeout expired, exit.");
			return false;
		}
		res = write(socket, buffer+start, end-start);
		if(res <= 0){
			ESP_LOGE(TAG, "writeall() - write failed.");
			return false;
		}
		start += res;
	}
	return true;
}

/* this is used to handle also partial read. if the pc on the other side sends too slowly and the flag is set we exit. */
bool readall(int socket, char *buffer, ssize_t end, int select_flag)
{
	ssize_t res;
	ssize_t start = 0;
	memset(buffer, '0', end); // clear input buffer before reading
	struct timeval input_check;
	fd_set rdfd;
	input_check.tv_sec = 2; input_check.tv_usec = 0; // for the select
	
	while(start < end){
		if(select_flag){
			FD_ZERO(&rdfd); FD_SET(socket, &rdfd); 
			res = select(socket+1, &rdfd, nullptr, nullptr, &input_check); // wait until there's something to read
			if(res==-1 || !FD_ISSET(socket, &rdfd)){ // select error or timeout expired
				ESP_LOGE(TAG, "readall() - select timeout expired, exit.");
				return false;
			}
		}
		res = read(socket, buffer+start, end-start);
		if(res <= 0){
			ESP_LOGE(TAG, "readall() - read failed.");
			return false;
		}
		start += res;
	}
	return true;
}

// serialize len bytes from value into the buffer
void serialize_uint(unsigned char *buffer, uint64_t value, uint8_t len)
{
 	// this approach is platform independent
	uint8_t i;
	for(i=0; i<len; i++){
		buffer[i] = value >> ((8*(len-1))-(8*i));
	}
}

// deserialize a buffer into a long (4 bytes)
long deserialize_long(unsigned char *buffer)
{
	long value = 0;
	value = buffer[0];
	value = value << 8;
	value += buffer[1];
	value = value << 8;
	value += buffer[2];
	value = value << 8;
	value += buffer[3];
	return value;
}

// this function handles the serialization of data to be sent to the computer
void serialize_data(pkt_data &it, char *buffer)
{
	memcpy(buffer, "DATA", 4); // just to tell the PC that we want to send sniffed data
	char *tmp = buffer+4; // tmp is used to work on the buffer as a pointer that moves along the buffer itself so we do not modify the buffer pointer passed to this function
	serialize_uint((unsigned char*)tmp, (uint64_t)(it.get_probe_req_payload_len()) + METADATA_LEN, 2); // how many bytes will be sent (metadata + probe request dump)
	tmp += 2;
	
	/* now we copy the metadata associated to the probe request, 32 bytes in total as defined by METADATA_LEN */
	strncpy(tmp, it.get_MAC().c_str(), MAC_LENGTH-1); // source MAC address of probe request (metadata)
	tmp += MAC_LENGTH-1;
	buffer[23] = (char)it.get_rssi(); // RSSI of probe request (metadata)
	// notice that rssi is a signed integer on 8 bits so we can simply copy it to the buffer
	tmp++;
	serialize_uint((unsigned char*)tmp, it.get_timestamp(), 8); // timestamp of probe request (metadata)
	tmp += 8;
	serialize_uint((unsigned char*)tmp, (uint64_t)it.get_seqnum(), 2); // sequence number of probe request (metadata)
	tmp += 2;
	serialize_uint((unsigned char*)tmp, (uint64_t)it.get_hash(), 4); // hash of probe request (metadata)
	tmp += 4;
	
	/* finally we copy the dump of the probe request */
	memcpy(tmp, it.get_probe_req_payload(), it.get_probe_req_payload_len()); // copy the probe request payload
}

/* djb2 hash function (xor variant) to compute the digest of the packet */
uint32_t djb2(unsigned char *data, size_t len){
	uint32_t hash = 5381;
	for(int i=0; i<len; i++){
		hash = hash * 33 ^ data[i];
	}
	return hash;
}

// connect to the access point
void ap_connect()
{
	EventBits_t uxBits;
	uxBits = xEventGroupWaitBits(wifi_event_group, CONNECTED_BIT, pdFALSE, pdTRUE, 0); // this is used to check if CONNECTED_BIT is set or not
	if((uxBits & CONNECTED_BIT) == 0){ // if already connected skip this step
		xEventGroupSetBits(wifi_event_group, RECONNECT_BIT); // (WiFi) set reconnect bit because we want to reconnect in case of disconnection
		ESP_ERROR_CHECK(esp_wifi_connect()); // connect to the AP
		xEventGroupWaitBits(wifi_event_group, CONNECTED_BIT, pdFALSE, pdTRUE, portMAX_DELAY); // wait forever until connection to the AP is ok
	}
}

/* simply turn off the onboard led of the esp32 */
void turn_off_led()
{
	gpio_pad_select_gpio(GPIO_NUM_2);
    gpio_set_direction(GPIO_NUM_2, GPIO_MODE_OUTPUT);
	gpio_set_level(GPIO_NUM_2, 0); // onboard LED off
}

// this task is used to toggle the onboard led. it will be deleted by a timer started in the main task.
void led_task(void *param)
{
	// setup desired GPIO
	gpio_pad_select_gpio(GPIO_NUM_2);
    gpio_set_direction(GPIO_NUM_2, GPIO_MODE_OUTPUT);
	
	double interval = 1000/(FREQUENCY*2); // time interval for onboard LED blinking (in milliseconds)
	const TickType_t task_delay = interval / portTICK_PERIOD_MS;
	uint8_t led_value = 1;
	
	for(;;){
		gpio_set_level(GPIO_NUM_2, led_value); // set onboard LED value
		led_value = !led_value; // toggle value for next iteration
		vTaskDelay(task_delay); // wait before toggling the value of the led
	}
}

// led timer callback to terminate the led blink task
void led_timer_callback(void *param){
	TaskHandle_t *led_task_handle = (TaskHandle_t*)param;
	if(*led_task_handle != nullptr){ // security check, calling vtaskdelete with null argument would terminate the main task and the application would crash
		vTaskDelete(*led_task_handle); // delete led blinking task
		*led_task_handle = nullptr; // set the task handler to nullptr for safety reason
		turn_off_led(); // this simply sets the onboard LED pin to 0 in order to turn it off
	}
}