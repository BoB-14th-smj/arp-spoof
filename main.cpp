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
    ArpPacket* arpPacket = (ArpPacket*)malloc(sizeof(ArpPacket) * (argc - 2)/2);

    for(int i=2;i<argc; i+=2){
        attack_arp(dev ,argv[i] , argv[i+1],  pcap);
    }

    free(arpPacket);


    pcap_close(pcap);
}
