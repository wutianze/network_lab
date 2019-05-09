#include "ip.h"
#include "icmp.h"
#include "rtable.h"
#include "arp.h"
#include "arpcache.h"

#include <stdio.h>
#include <stdlib.h>

// forward the IP packet from the interface specified by longest_prefix_match, 
// when forwarding the packet, you should check the TTL, update the checksum,
// determine the next hop to forward the packet, then send the packet by 
// iface_send_packet_by_arp
void ip_forward_packet(u32 ip_dst, char *packet, int len)
{
	struct iphdr *ip = packet_to_ip_hdr(packet);
	rt_entry_t* e = longest_prefix_match(ip->daddr);
	if(e == NULL){
		icmp_send_packet(packet,len,ICMP_DEST_UNREACH,ICMP_ECHOREPLY);
		free(packet);
		return;
	}
	ip->ttl -=1;
	if(ip->ttl <= 0){
		icmp_send_packet(packet,len,ICMP_TIME_EXCEEDED,ICMP_ECHOREPLY);
		free(packet);
		return;
	}
	ip->checksum = ip_checksum(ip);
	memcpy(((struct ether_header*)packet)->ether_shost, e->iface->mac,ETH_ALEN);
	u32 nH = e->gw;
	if(nH == 0){
		nH = ntohl(ip->daddr);
	}
	iface_send_packet_by_arp(e->iface,nH,packet,len);
	fprintf(stderr, "TODO: forward ip packet.\n");
}

// handle ip packet
//
// If the packet is ICMP echo request and the destination IP address is equal to
// the IP address of the iface, send ICMP echo reply; otherwise, forward the
// packet.
void handle_ip_packet(iface_info_t *iface, char *packet, int len)
{
	struct iphdr *ip = packet_to_ip_hdr(packet);
	u32 daddr = ntohl(ip->daddr);
	struct icmphdr* checkIcmp = (struct imcphdr*)(packet + ETHER_HDR_SIZE + IP_HDR_SIZE(ip));
	if (daddr == iface->ip && checkIcmp->type == ICMP_ECHOREQUEST){
		icmp_send_packet(packet,len,0,0);
		fprintf(stderr, "TODO: reply to the sender if it is ping packet.\n");
		free(packet);
	}
	else {
		ip_forward_packet(daddr, packet, len);
	}
}
