#include "arp.h"
#include "base.h"
#include "types.h"
#include "packet.h"
#include "ether.h"
#include "arpcache.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// #include "log.h"

// send an arp request: encapsulate an arp request packet, send it out through
// iface_send_packet
void arp_send_request(iface_info_t *iface, u32 dst_ip)
{
	char* packet;
	packet = (char*)malloc(ETHER_HDR_SIZE + sizeof(struct ether_arp));
	struct ether_header* eH = (struct ether_header*)(packet);
	memcpy(eH->ether_shost, iface->mac, ETH_ALEN);
	int i=0;
	for(; i < ETH_ALEN; i++){
		 eH->ether_dhost[i] = u8(255);
	}
	eH->ether_type = htons(ETH_P_ARP);

	struct ether_arp* eA = (struct ether_arp*)(packet + ETHER_HDR_SIZE);
	eA->arp_hrd = htons(1);
	eA->arp_pro = htons(0x0800);
	eA->arp_hln = 6;
	eA->arp_pln = 4;
	eA->arp_op = htons(ETH_REQUEST);
	memcpy(eA->arp_sha, iface->mac, ETH_ALEN);
	eA->arp_spa = htonl(iface->ip);
	eA->arp_tpa = htonl(dst_ip);
	memset(eA->arp_tha,0,ETH_ALEN);
	iface_send_packet(iface, packet, ETHER_HDR_SIZE+sizeof(struct ether_arp));
	fprintf(stderr, "TODO: send arp request when lookup failed in arpcache.\n");
}

// send an arp reply packet: encapsulate an arp reply packet, send it out
// through iface_send_packet
void arp_send_reply(iface_info_t *iface, struct ether_arp *req_hdr)
{
	char* packet;
	packet = (char*)malloc(ETHER_HDR_SIZE + sizeof(struct ether_arp));
	struct ether_header* eH;
	eH = (struct ether_header*)packet;
	struct ether_arp*eA = (struct eA*)(packet + ETHER_HDR_SIZE);
	memcpy(eH->ether_shost, iface->mac, ETH_ALEN);
	memcpy(eH->ether_dhost, req_hdr->arp_sha, ETH_ALEN);
	eH->ether_type = htons(ETH_P_ARP);
	eA->arp_hrd = htons(0x01);
	eA->arp_pro = htons(0x0800);
	eA->arp_hln = 6;
	eA->arp_pln = 4;
	eA->arp_op = htons(ARPOP_REPLY);
	eA->arp_spa = htonl(iface->ip);
	eA->arp_tpa = req_hdr->arp_spa;
	memcpy(eA->arp_sha,iface->mac,ETH_ALEN);
	memcpy(eA->arp_tha,req_hdr->arp_sha,ETH_ALEN);
	iface_send_packet(iface,packet,sizeof(struct ether_arp)+ETHER_HDR_SIZE);
	fprintf(stderr, "TODO: send arp reply when receiving arp request.\n");
}

void handle_arp_packet(iface_info_t *iface, char *packet, int len)
{
	struct ether_header* eh;
	struct ether_arp* eA;
	eh = (struct ether_header*)(packet);
	eA = (struct ether_arp*)(packet + ETHER_HDR_SIZE);
	if(ntohs(eA->arp_op) == ARPOP_REQUEST){
		if(ntohl(eA->arp_tpa) == iface->ip){
			arp_send_reply(iface, eA);
			arpcache_insert(ntohl(eA->arp_spa),eA->arp_sha);
		}
	}
	else if(ntohs(eA->arp_op) == ARPOP_REPLY){
		if(ntohl(eA->arp_tpa) == iface->ip){
			arpcache_insert(ntohl(eA->arp_spa), eA->arp_sha);
		}
	}
	//free(packet);
	fprintf(stderr, "TODO: process arp packet: arp request & arp reply.\n");
}

// send (IP) packet through arpcache lookup 
//
// Lookup the mac address of dst_ip in arpcache. If it is found, fill the
// ethernet header and emit the packet by iface_send_packet, otherwise, pending 
// this packet into arpcache, and send arp request.
void iface_send_packet_by_arp(iface_info_t *iface, u32 dst_ip, char *packet, int len)
{
	struct ether_header *eh = (struct ether_header *)packet;
	memcpy(eh->ether_shost, iface->mac, ETH_ALEN);
	eh->ether_type = htons(ETH_P_IP);

	u8 dst_mac[ETH_ALEN];
	int found = arpcache_lookup(dst_ip, dst_mac);
	if (found) {
		// log(DEBUG, "found the mac of %x, send this packet", dst_ip);
		memcpy(eh->ether_dhost, dst_mac, ETH_ALEN);
		iface_send_packet(iface, packet, len);
	}
	else {
		// log(DEBUG, "lookup %x failed, pend this packet", dst_ip);
		arpcache_append_packet(iface, dst_ip, packet, len);
	}
}
