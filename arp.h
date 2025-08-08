#pragma once
#pragma pack(1)
#include <cstdint>
#include <stdint.h>
#include <stdio.h>
#include <netinet/in.h>
#include <string>
#include "ethernet.h"



uint32_t stoi_ip(std::string ip);
std::string get_my_ip(char* interface);
struct Arp {
private:
    uint16_t h_type;
    uint16_t p_type;

    uint8_t h_length;
    uint8_t p_length;
    uint16_t operaton;

    uint8_t s_mac_[6];
    uint32_t s_ip_;

    uint8_t t_mac_[6];
    uint32_t t_ip_;


public:
    Arp();
    Arp(uint8_t* smac, uint8_t* tmac, uint32_t sip, uint32_t tip, uint16_t op_){
        set_smac(smac);
        set_tmac(tmac);
        set_sip(sip);
        set_tip(tip);
        set_others(op_);
    }
    Arp(std::string smac, std::string tmac, std::string sip, std::string tip, uint16_t op_){
        if(op_ == 0x1 && tmac == "ff:ff:ff:ff:ff:ff"){
            std::string zero_mac = "00:00:00:00:00:00";
            set_tmac(zero_mac);
        }else{
            set_tmac(tmac);
        }

        set_smac(smac);
        set_sip(sip);
        set_tip(tip);
        set_others(op_);

    }

    uint16_t get_operation(void) { return operaton; }
    uint8_t* get_smac(void) { return s_mac_; }
    uint8_t* get_tmac(void) { return t_mac_; }
    uint32_t get_sip(void) { return s_ip_; }
    uint32_t get_tip(void) { return t_ip_; }


    void set_smac(uint8_t* smac){
        for (int i=0;i<6;i++){
            s_mac_[i] = smac[i];
        }
    }

    void set_smac(std::string smac){
        stoi_mac(smac, s_mac_);
    }

    void set_tmac(uint8_t* tmac){
        for (int i=0;i<6;i++){
            t_mac_[i] = tmac[i];
        }
    }

    void set_tmac(std::string tmac){
        stoi_mac(tmac, t_mac_);
    }

    void set_sip(uint32_t sip){
        s_ip_ = ntohl(sip);
    }

    void set_sip(std::string sip){
        s_ip_ = ntohl(stoi_ip(sip));
    }

    void set_tip(uint32_t tip){
        t_ip_ = ntohl(tip);

    }

    void set_tip(std::string tip){
        t_ip_ = ntohl(stoi_ip(tip));
    }

    void set_others(uint16_t op_){
        h_type = ntohs(0x0001);
        p_type = ntohs(0x0800);
        h_length = 0x6;
        p_length = 0x4;
        operaton = ntohs(op_);
    }

    void print_arp(void){
        printf("%04x ", h_type);
        printf("%04x ", p_type);
        printf("%02x ", h_length);
        printf("%02x ", p_length);

        printf("%04x ", operaton);
        for (int i=0;i<6;i++){
            printf("%02x ", s_mac_[i]);
        }
        printf("%02x %02x %02x %02x ", (s_ip_ >> 24) & 0xFF, (s_ip_ >> 16) & 0xFF, (s_ip_ >> 8) & 0xFF, (s_ip_) & 0xFF);

        printf("%04x ", operaton);
        for (int i=0;i<6;i++){
            printf("%02x ", t_mac_[i]);
        }
        printf("%02x %02x %02x %02x ", (t_ip_ >> 24) & 0xFF, (t_ip_ >> 16) & 0xFF, (t_ip_ >> 8) & 0xFF, (t_ip_) & 0xFF);


    }



};


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
