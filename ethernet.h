#pragma once
#include <cstdint>
#include <stdint.h>
#include <stdio.h>
#include <netinet/in.h>
#include <string>
using namespace std;

void stoi_mac(std::string mac, uint8_t* smac);
std::string get_my_mac(char* interface);
std::string get_command_output(string command);


struct Ethernet {
private:
    uint8_t d_mac_[6];
    uint8_t s_mac_[6];
    uint16_t e_type;

public:
    Ethernet();
    Ethernet(uint8_t* dmac, uint8_t* smac, uint16_t e_type){
        set_dmac(dmac);
        set_smac(smac);
        set_e_type(e_type);
    };

    Ethernet(std::string dmac, std::string smac, uint16_t e_type){
        set_dmac(dmac);
        set_smac(smac);
        set_e_type(e_type);
    };

    uint8_t* get_d_mac(void) { return d_mac_; }
    uint8_t* get_s_mac(void) { return s_mac_; }
    uint16_t get_ether_type(void) { return ntohs(e_type); }

    void set_e_type(uint16_t etype){
        e_type = (etype);

    }

    void set_smac(uint8_t* smac){
        for (int i=0;i<6;i++){
            s_mac_[i] = smac[i];
        }
    }

    void set_smac(std::string smac){
        stoi_mac(smac, s_mac_);
    }

    void set_dmac(uint8_t* dmac){
        for (int i=0;i<6;i++){
            d_mac_[i] = dmac[i];
        }
    }

    void set_dmac(std::string dmac){
        stoi_mac(dmac, d_mac_);
    }

    void print_ethernet(void){
        for(int i=0;i<6;i++){
            printf("%02x " , d_mac_[i]);
        }
        for(int i=0;i<6;i++){
            printf("%02x " , s_mac_[i]);
        }
        printf("%04x", ntohs(e_type));


    }

};
