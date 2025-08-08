#pragma once
#pragma pack(1)
#include "ethernet.h"
#include "arp.h"

struct ArpPacket{
private:
    Ethernet ethernet;
    Arp arp;

public:
    ArpPacket();
    ArpPacket(Ethernet* ethernet_, Arp* arp_) : ethernet(*ethernet_), arp(*arp_){};

    Ethernet get_ethernet(void){
        return ethernet;
    }

    Arp get_arp(void){
        return arp;
    }
};
