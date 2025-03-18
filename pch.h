#include <stdio.h>
#include <cstdio>
#include <pcap.h>
#include <string.h>
#include <sys/types.h>  //socket
#include <sys/socket.h>  //socket
#include <net/if.h>  //ifreq
#include <sys/ioctl.h>  //ioctl
#include <arpa/inet.h>

#include "arphdr.h"
#include "ethhdr.h"

void GetMacAddressFromInterface(const char *interface_name, char *mac_addr, char *ip_addr);
void arpRequest(pcap_t *pcap, char *src_ip, char *dst_ip, char *src_mac, char *dst_mac);
void captureArpReply(pcap_t *pcap, char *src_ip, char *mac_addr);
void arpReplyAttack(pcap_t *pcap, char *src_ip, char *dst_ip, char *src_mac, char *dst_mac);
