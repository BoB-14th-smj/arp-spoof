#include "ethernet.h"
#include <cstdint>
#include <stdio.h>
#include <string>


using namespace std;

string get_command_output(string command){
    string result;
    FILE *stream;
    uint8_t BUF_SIZE = 128;
    char buffer[BUF_SIZE];

    stream = popen(command.c_str(), "r");
    if(stream){
        while(fgets(buffer, BUF_SIZE, stream) != NULL){
            result.append(buffer);
        }
        return result;

    }
    pclose(stream);
    return "-1";
}

string get_my_mac(char* interface){
    string if_ = interface;

    string command =  "cat /sys/class/net/" + if_ + "/address";
    string result = get_command_output(command);
    printf("%s", result.c_str());
    return result;
}


void stoi_mac(std::string mac, uint8_t* smac){
    for(int i=0;i<6;i++){
        std::string byte = mac.substr(i*3, 2);
        uint8_t b = std::stoi(byte.c_str(), nullptr, 16);
        smac[i] = b;
    }

    // for (int i=0;i<6;i++){
    //     printf("%02X ", smac[i]);
    // }
}
