#include "icmp.h"
#include "ip.h"
#include "rtable.h"
#include "arp.h"
#include "base.h"

#include <stdio.h>
#include <stdlib.h>

// send icmp packet
void icmp_send_packet(const char *in_pkt, int len, u8 type, u8 code)
{
	char* packetSend;
	struct ether_header* eH = (struct ether_header*)in_pkt;
	struct iphdr* ipH = (struct iphdr*)(in_pkt + ETHER_HDR_SIZE);
	struct icmphdr* icmpH = (struct icmphdr*)(in_pkt + ETHER_HDR_SIZE + IP_HDR_SIZE(ipH));
	int sendL = len;
	if(type ==0 && code == 0){
		packetSend = (char*)malloc(len);
		struct ether_header* eHS = (struct ether_header*)packetSend;
        	struct iphdr* ipHS = (struct iphdr*)(packetSend + ETHER_HDR_SIZE);
        	struct icmphdr* icmpHS = (struct icmphdr*)(packetSend + ETHER_HDR_SIZE + IP_HDR_SIZE(ipH));
		memcpy(eHS->ether_shost,eH->ether_dhost,ETH_ALEN);
		//memcpy(eHS->ether_dhost,eH->ether_shost,ETH_ALEN);
		ip_init_hdr(ipHS,ntohl(ipH->daddr),ntohl(ipH->saddr),len - ETHER_HDR_SIZE, IPPROTO_ICMP);
		icmpH->type = 0;
		icmpH->code = 0;
		memcpy(((char*)icmpHS) + 4,((char*)icmpH) + 4,len-ETHER_HDR_SIZE-IP_HDR_SIZE(ipH));
		icmpHS->checksum = icmp_checksum(icmpHS,len-ETHER_HDR_SIZE-IP_HDR_SIZE(ipH));
	}else{
		sendL = ETHER_HDR_SIZE + 2*IP_HDR_SIZE(ipH) + 16;
		packetSend = (char*)malloc(ETHER_HDR_SIZE + IP_HDR_SIZE(ipH) + 8 + IP_HDR_SIZE(ipH) + 8);
                struct ether_header* eHS = (struct ether_header*)packetSend;
                struct iphdr* ipHS = (struct iphdr*)(packetSend + ETHER_HDR_SIZE);
                struct icmphdr* icmpHS = (struct icmphdr*)(packetSend + ETHER_HDR_SIZE + IP_HDR_SIZE(ipH));
                eHS->ether_type = htons(ETH_P_IP);
		memcpy(eHS->ether_dhost,eH->ether_shost,ETH_ALEN);
                u32 tmpS = 0;
		ip_init_hdr(ipHS,ntohl(ipH->daddr),tmpS,sendL - ETHER_HDR_SIZE, IPPROTO_ICMP);
		//the source ip will be initialized in ip_send_packet

		icmpH->type = type;
                icmpH->code = code;               
		memset(((char*)icmpHS)+4,0,4);
                memcpy(((char*)icmpHS) + 8,((char*)ipH),IP_HDR_SIZE(ipH)+8);
                icmpHS->checksum = icmp_checksum(icmpHS,sendL-ETHER_HDR_SIZE-IP_HDR_SIZE(ipH));
	}
	ip_send_packet(packetSend,sendL);
	fprintf(stderr, "TODO: malloc and send icmp packet.\n");
}
