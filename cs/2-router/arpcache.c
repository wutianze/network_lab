#include "arpcache.h"
#include "arp.h"
#include "ether.h"
#include "packet.h"
#include "icmp.h"

#include "ip.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

static arpcache_t arpcache;

// initialize IP->mac mapping, request list, lock and sweeping thread
void arpcache_init()
{
	bzero(&arpcache, sizeof(arpcache_t));

	init_list_head(&(arpcache.req_list));

	pthread_mutex_init(&arpcache.lock, NULL);

	pthread_create(&arpcache.thread, NULL, arpcache_sweep, NULL);
}

// release all the resources when exiting
void arpcache_destroy()
{
	pthread_mutex_lock(&arpcache.lock);

	struct arp_req *req_entry = NULL, *req_q;
	list_for_each_entry_safe(req_entry, req_q, &(arpcache.req_list), list) {
		struct cached_pkt *pkt_entry = NULL, *pkt_q;
		list_for_each_entry_safe(pkt_entry, pkt_q, &(req_entry->cached_packets), list) {
			list_delete_entry(&(pkt_entry->list));
			free(pkt_entry->packet);
			free(pkt_entry);
		}

		list_delete_entry(&(req_entry->list));
		free(req_entry);
	}

	pthread_kill(arpcache.thread, SIGTERM);

	pthread_mutex_unlock(&arpcache.lock);
}

// lookup the IP->mac mapping
//
// traverse the table to find whether there is an entry with the same IP
// and mac address with the given arguments
int arpcache_lookup(u32 ip4, u8 mac[ETH_ALEN])
{
	fprintf(stderr,"arpcache_lookup,ip4:%x\n",ip4);
	
	pthread_mutex_lock(&arpcache.lock);
	int i=0;
	for(;i<MAX_ARP_SIZE;i++){
		if(arpcache.entries[i].ip4 == ip4 && arpcache.entries[i].valid == 1){
			int j=0;
			for(;j<ETH_ALEN;j++){
				fprintf(stderr,"lookup mac[%d]=%d\n",j,arpcache.entries[i].mac[j]);
				mac[j] = arpcache.entries[i].mac[j];
			}
			pthread_mutex_unlock(&arpcache.lock);
			fprintf(stderr,"find one\n");
			return 1;
		}
	}
	pthread_mutex_unlock(&arpcache.lock);
	fprintf(stderr, "TODO: lookup ip address in arp cache.\n");
	return 0;
}

// append the packet to arpcache
//
// Lookup in the list which stores pending packets, if there is already an
// entry with the same IP address and iface (which means the corresponding arp
// request has been sent out), just append this packet at the tail of that entry
// (the entry may contain more than one packet); otherwise, malloc a new entry
// with the given IP address and iface, append the packet, and send arp request.
void arpcache_append_packet(iface_info_t *iface, u32 ip4, char *packet, int len)
{
	fprintf(stderr,"arpcache_append_packet,ip4:%x\n",ip4);
	pthread_mutex_lock(&arpcache.lock);
	struct arp_req *e,*n;
	list_for_each_entry_safe(e,n,&(arpcache.req_list),list){
		fprintf(stderr,"e->iface:%x,iface->ip:%x\n",(e->iface)->ip,iface->ip);
		if((e->iface)->ip == iface->ip && e->ip4 == ip4){
			//if already has a same req,then add to its waiting packets
			fprintf(stderr,"already has a same req\n");
			struct cached_pkt*newP = (struct cached_pkt*)malloc(sizeof(struct cached_pkt));
			newP->packet = packet;
			newP->len = len;
			list_add_tail(&(newP->list),&(e->cached_packets));
			pthread_mutex_unlock(&arpcache.lock);
			return;
		}
	}
	//if no such req yet,create one and this packet is the first
	struct arp_req* newR = (struct arp_req*)malloc(sizeof(struct arp_req));
	newR->iface = iface;
	newR->ip4 = ip4;
	newR->sent = time(0);
	newR->retries = 0;
	init_list_head(&(newR->cached_packets));
	list_add_tail(&(newR->list), &(arpcache.req_list));
	
	struct cached_pkt *newP;
	newP = (struct cached_pkt *)malloc(sizeof(struct cached_pkt));
	newP->packet = packet;
	newP->len = len;
	list_add_tail(&(newP->list), &(newR->cached_packets));	
	pthread_mutex_unlock(&arpcache.lock);
	
	//finally send this new req
	arp_send_request(iface, ip4);	
	fprintf(stderr, "TODO: append the ip address if lookup failed, and send arp request if necessary.\n");
}

// insert the IP->mac mapping into arpcache, if there are pending packets
// waiting for this mapping, fill the ethernet header for each of them, and send
// them out
void arpcache_insert(u32 ip4, u8 mac[ETH_ALEN])
{
	int mi = 0;
	for(;mi<ETH_ALEN;mi++){
		fprintf(stderr,"mi[%d]=%d\n",mi,mac[mi]);
	}
	fprintf(stderr, "TODO: insert ip->mac entry, and send all the pending packets.\n");
	int i=0;
	for(;i<MAX_ARP_SIZE;i++){
		if(arpcache.entries[i].valid == 0){
			pthread_mutex_lock(&arpcache.lock);
			arpcache.entries[i].ip4 = ip4;
			memcpy(arpcache.entries[i].mac, mac, ETH_ALEN);
			arpcache.entries[i].added = time(0);
			arpcache.entries[i].valid = 1;
			pthread_mutex_unlock(&arpcache.lock);
			break;
		}
	}
	if(i == MAX_ARP_SIZE){
		int r = rand()%MAX_ARP_SIZE;
		pthread_mutex_lock(&arpcache.lock);
		arpcache.entries[r].ip4 = ip4;
		memcpy(arpcache.entries[r].mac, mac, ETH_ALEN);
		arpcache.entries[r].added = time(NULL);
		arpcache.entries[r].valid = 1;
		pthread_mutex_unlock(&arpcache.lock);
	}
	fprintf(stderr,"then handle pending packets\n");
	struct arp_req *e=NULL,*n;
	list_for_each_entry_safe(e,n,&(arpcache.req_list),list){
		if(ip4 == e->ip4){
			fprintf(stderr,"ip4:%x\n",ip4);
			struct cached_pkt *pe=NULL,*pn;
			list_for_each_entry_safe(pe,pn,&(e->cached_packets),list){
				char* pS = pe->packet;
				int len = pe->len;
				struct ether_header* eH = (struct ether_header*)(pS);
				memcpy(eH->ether_dhost,mac,ETH_ALEN);
				struct iphdr* deIp = (struct iphdr*)(pS + ETHER_HDR_SIZE);
				
				fprintf(stderr,"iface_send in insert,ipsaddr:%x,ipdaddr:%x\n",deIp->saddr,deIp->daddr);
				if(ntohs(eH->ether_type) == ETH_P_IP){
					struct icmphdr* icmpH = (struct icmphdr*)(pS + ETHER_HDR_SIZE + IP_HDR_SIZE(deIp));
					fprintf(stderr,"iface_send in insert,icmptype:%d,icmpcode:%d\n",icmpH->type,icmpH->code);
	}
				iface_send_packet(e->iface,pS,len);
				list_delete_entry(&(pe->list));
			}
		list_delete_entry(&(e->list));
		}
	}
}

// sweep arpcache periodically
//
// For the IP->mac entry, if the entry has been in the table for more than 15
// seconds, remove it from the table.
// For the pending packets, if the arp request is sent out 1 second ago, while 
// the reply has not been received, retransmit the arp request. If the arp
// request has been sent 5 times without receiving arp reply, for each
// pending packet, send icmp packet (DEST_HOST_UNREACHABLE), and drop these
// packets.
void *arpcache_sweep(void *arg) 
{
	while (1) {
		sleep(1);
		time_t nowT = time(0);
		pthread_mutex_lock(&arpcache.lock);
		int i=0;
		for(;i<MAX_ARP_SIZE;i++){
			if(arpcache.entries[i].valid == 1 && nowT-arpcache.entries[i].added >= 15){
				arpcache.entries[i].valid = 0;
				arpcache.entries[i].ip4 = 0;
			}
		}
		struct arp_req *e,*n;
		list_for_each_entry_safe(e,n,&(arpcache.req_list),list){
		if(nowT - e->sent>1){
			if(e->retries<5){
				arp_send_request(e->iface,e->ip4);
				e->sent = nowT;
				e->retries += 1;
			}else{
				fprintf(stderr,"extend 5 tries,send icmp\n");
				struct cached_pkt *pe,*pn;
				list_for_each_entry_safe(pe,pn,&(e->cached_packets),list){
					pthread_mutex_unlock(&arpcache.lock);
					icmp_send_packet(pe->packet,pe->len,3,1);
					pthread_mutex_lock(&arpcache.lock);
					list_delete_entry(&(pe->list));
				}
				list_delete_entry(&(e->list));
			}
		}
	}
		pthread_mutex_unlock(&arpcache.lock);
		fprintf(stderr, "TODO: sweep arpcache periodically: remove old entries, resend arp requests .\n");
	}

	return NULL;
}
