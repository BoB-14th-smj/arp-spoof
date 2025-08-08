#pragma once
#pragma pack(1)
#include "ethernet.h"
#include "arp.h"
#include "ip.h"
#include "mac.h"

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

struct Info{
    Mac s_mac_;
    Ip s_ip_;
    Mac d_mac_;
    Ip d_ip_;
    Mac my_mac_;
    Ip my_ip_;

    Info(char* dev, Mac s_mac, Ip s_ip, Mac d_mac, Ip d_ip){
        s_mac_ = s_mac;
        s_ip_ = s_ip;
        d_mac_ = d_mac;
        d_ip_ = d_ip;
        my_mac_ = get_my_mac(dev);
        my_ip_ = get_my_ip(dev);
    }

    Info(char* dev, ArpPacket& packet, Mac* mac) {
        Ethernet ethernet = packet.get_ethernet();
        Arp arp = packet.get_arp();

        s_mac_ = Mac(ethernet.get_s_mac());
        d_mac_ = *mac;
        s_ip_ = Ip(arp.get_sip());
        d_ip_ = arp.get_tip();

        my_mac_ = get_my_mac(dev);
        my_ip_ = get_my_ip(dev);
    }



    void print_info(void){
        s_mac_.print_mac();
        s_ip_.print_ip();
        d_mac_.print_mac();
        s_ip_.print_ip();
        my_mac_.print_mac();
        my_ip_.print_ip();



    }
};

