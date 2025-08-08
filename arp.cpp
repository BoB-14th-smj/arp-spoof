#include "arp.h"
#include "ethernet.h"

using namespace std;

void construct_arp_packet(Ethernet* ethernet, Arp* arp){


}

uint32_t stoi_ip(std::string ip){
    // printf("%s\n", ip.c_str());
    uint32_t result = 0;
    uint32_t pos = 0;
    uint32_t npos=0;
    for(int i=0;i<3;i++){
        npos = ip.find(".", pos);
        std::string byte = ip.substr(pos, npos-pos);
        // printf("%s\n", byte.c_str());
        result |= std::stoi(byte.c_str(), nullptr, 10);
        pos = npos+1;
        result  = result << 8;
    }
    std::string byte = ip.substr(pos);
    // printf("%s\n", byte.c_str());
    result += std::stoi(byte.c_str(), nullptr, 10);


    // printf("%x\n", result);
    return result;

}

string get_my_ip(char* interface){
    string if_ = interface;

    // string command =  "hostname -I";
    string command = "ip -4 addr show " + if_ ;
    string result = get_command_output(command);
    uint8_t index = result.find("inet");
    // printf("\n\n\n%d", index);
    size_t index2 = result.find("/" ,index);
    string final = result.substr(index+4, index2 - index);
    index2 = final.find("/");
    final = final.substr(0, index2);
    // printf("%s", final.c_str());
    return final;
}
