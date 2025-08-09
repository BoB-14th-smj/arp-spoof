#pragma once
#include <stdint.h>
#include <string>
#include <cstdint>
#include <cstring>


struct Mac{
public:
    uint8_t mac_[6];


    Mac() {}
    Mac(const Mac& r) { memcpy(this->mac_, r.mac_, 6); }
    Mac(const uint8_t* r) { memcpy(this->mac_, r, 6); }
    Mac(const std::string& r){
        sscanf(r.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               &mac_[0], &mac_[1], &mac_[2],
               &mac_[3], &mac_[4], &mac_[5]);
    }

    void print_mac(void){
        for(int i=0;i<6;i++){
            printf("%02x " ,mac_[i]);
        }
        printf("\n");


    }

    uint8_t* bytes() { return mac_; }

    bool operator == (const Mac& r) const { return memcmp(mac_, r.mac_, 6) == 0; }

};
