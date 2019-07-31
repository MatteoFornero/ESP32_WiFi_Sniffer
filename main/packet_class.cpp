#include "wifi_sniffer.h"
using namespace std;

pkt_data::pkt_data()
{
	src_MAC = "\0";
	rssi = 0;
	timestamp = 0;
	seq_number = 0;
	hash = 0;
	probe_req_payload = nullptr;
	probe_req_payload_len = 0;
}

pkt_data::pkt_data(string &MAC_source, int8_t signal_strength, uint64_t pkt_timestamp, uint16_t pkt_seq, uint32_t pkt_digest, unique_ptr<char[]> pkt_payload, uint16_t pkt_payload_len)
{
	src_MAC = MAC_source;
	rssi = signal_strength;
	timestamp = pkt_timestamp;
	seq_number = pkt_seq;	
	hash = pkt_digest;
	probe_req_payload = move(pkt_payload);
	probe_req_payload_len = pkt_payload_len;
}

/* Returns the MAC of the device that sent the probe request. MAC can be valid globally or locally (to avoid device tracking and identification). */
string pkt_data::get_MAC()
{
	return src_MAC;
}

/* Returns the signal strength of the received probe request. */
int8_t pkt_data::get_rssi()
{
	return rssi;
}

/* Returns the timestamp of the received probe request. */
uint64_t pkt_data::get_timestamp()
{
	return timestamp;
}

/* Returns the sequence number of the received probe request. */
uint16_t pkt_data::get_seqnum()
{
	return seq_number;
}

/* Returns the hash of the probe request computed with the DJB2 algorithm. */
uint32_t pkt_data::get_hash()
{
	return hash;
}

/* Returns a the pointer to the first byte of the dump of the payload of the probe request. */
char* pkt_data::get_probe_req_payload()
{
	return probe_req_payload.get();
}

/* Returns the size (in bytes) of the dump of the payload of the probe request. */
uint16_t pkt_data::get_probe_req_payload_len()
{
	return probe_req_payload_len;
}