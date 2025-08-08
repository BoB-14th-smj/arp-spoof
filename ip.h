#pragma once

#include "arp.h"
#include <cstdint>
#include <netinet/in.h>
#include <string>

struct Ip {
public:
    uint32_t ip_;
    Ip() {}
    Ip(uint32_t r) {
        ip_ = ntohl(r); }
    Ip(std::string r){
        ip_ = stoi_ip(r);
    }

    void print_ip(void){
        printf("%02x %02x %02x %02x\n", (ip_ >> 24) & 0xFF, (ip_ >> 16) & 0xFF, (ip_ >> 8) & 0xFF, (ip_) & 0xFF);
    }
};
