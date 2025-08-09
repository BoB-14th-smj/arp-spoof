#pragma once
#include <cstdint>
#include "ethernet.h"
#include "arp.h"
#include "packet.h"
#include <string>
#include <pcap/pcap.h>

void arp_request(pcap_t* pcap, char* dev, std::string d_mac_, std::string s_mac_, char* sender_ip, char* target_ip, uint16_t op_);
ArpPacket* arp_reply(pcap_t* pcap, char* dev, std::string d_mac_, std::string s_mac_, char* sender_ip, char* target_ip);
ArpPacket* get_packet(pcap_t* pcap, std::string mac_);
ArpPacket* attack_arp(char* dev, char* sender_ip, char* target_ip, pcap_t* pcap, Mac* target_mac_add);
void arp_reply(pcap_t* pcap, ArpPacket* packet);
