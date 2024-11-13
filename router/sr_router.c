/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"
#include "string.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
	/* REQUIRES */
	assert(sr);

	/* Initialize cache and cache cleanup thread */
	sr_arpcache_init(&(sr->cache));

	pthread_attr_init(&(sr->attr));
	pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
	pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
	pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
	pthread_t thread;

	pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);

	/* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void handleARPpacket(struct sr_instance* sr, char* interface, uint8_t* packet, uint8_t len) {
	/* convert dest IP addr to dest MAC addr*/

	sr_arp_hdr_t* arp_header = (sr_arp_hdr_t*) (packet+sizeof(sr_ethernet_hdr_t));

	/*TODO: determine if destined to us or not*/
	/*TODO: determine if response or request */
	/*TODO: change this to work for all 4 cases based on the two specified above*/
	/*TODO: disregard above, we will assume all requests/resonses are intended for us,
	 * no need to forward ones that aren't*/

	unsigned short arpOp = ntohs(arp_header->ar_op);

	printf(">>---ARP optype (endianned): %hu <--- :)\n", arpOp);

	/*if it's a response, we add it to the cache and return*/
	if (arpOp == arp_op_reply) {
		sr_arpcache_insert(&(sr->cache), arp_header->ar_sha, arp_header->ar_sip);
		printf("Caching ARP reply\n");
		return;
	} /*end of ARP reply handling*/


	/*FOLLOWING IS FOR IF ITS A REQUEST (CURRENTLY IGNORES REQUESTS SENT TO OTHER MACHINES*/

	unsigned short hw_addr = arp_header->ar_hrd;
	uint32_t target_IP = arp_header->ar_tip;
	printf("____target IP: %d\n", target_IP);


	struct sr_if* iface = sr->if_list;

	while (iface != NULL) {
		printf("\n---Responding to ARP request");
		printf(" on %s\n", iface->name);
		if (iface->ip == target_IP) {
			/* send response for ARP request */
			/*Creating the response packet*/
			uint8_t* buffer = malloc(sizeof(sr_arp_hdr_t)+sizeof(sr_ethernet_hdr_t));
			unsigned char* src_addr = iface->addr;
			sr_ethernet_hdr_t* ethheader = (sr_ethernet_hdr_t*)buffer;
			sr_arp_hdr_t* arpheader = (sr_arp_hdr_t*)(buffer+sizeof(sr_ethernet_hdr_t));
			/* generate eth header */
			memcpy(ethheader->ether_dhost, arp_header->ar_sha, 6);
			memcpy(ethheader->ether_shost, iface->addr, 6);
			ethheader->ether_type = htons(ethertype_arp);
			/* generate arp header */
			arpheader->ar_hrd = htons(arp_hrd_ethernet);
			arpheader->ar_pro = htons(ethertype_ip);
			arpheader->ar_hln = 6;
			arpheader->ar_pln = sizeof(ethertype_ip);
			arpheader->ar_op = htons(arp_op_reply);
			memcpy(arpheader->ar_tha, src_addr, 6);
			memcpy(arpheader->ar_sha, arp_header->ar_sha, 6);
			arpheader->ar_tip = iface->ip;
			arpheader->ar_sip = arp_header->ar_tip;

			/*Printing out packet for debugging purposes*/
			/*
			printf("____response buffer: ");
			int i=0;
			for (i=0; i<sizeof(sr_ethernet_hdr_t)+sizeof(sr_arp_hdr_t); i++) {
				printf("%02x ", buffer[i]);
			}
			printf("\n");
			*/

			sr_send_packet(sr, buffer, sizeof(sr_ethernet_hdr_t)+sizeof(sr_arp_hdr_t), iface->name);

			return;
		}

		iface = iface->next;
	}

	/*all following code should never be executed for the purposes of Part 1
	 * TODO: comment it all out
	 * */

	/*if it was a request and was not destined for our machine's IP, we fucked up, so just forward the packet*/
	/*struct sr_arpreq* req = sr_arpcache_queuereq(&(sr->cache), target_IP, packet, len, interface);

	/* look up dest IP addr in ARP cache to check if we already know its MAC address. */
	/* sr_arpcache_lookup(sr->cac)*/
	/*sr_arpcache_sweepreqs(sr);

	/* if in ARP cache, then reply to src MAC addr with the dest MAC addr. */

	/* if NOT in ARP cache, then we want to forward the ARP request to all the other interfaces (except for source). */

	/* TODO: we send ARP requests and responses (no we don't, arpcache.c does and that hasn't been written yet)
	 *we handle requests (yay go team), but we don't yet handle ARP responses. (now we do ;)*/
}

void handleIPpacket(struct sr_instance* sr, char* interface, uint8_t* packet, unsigned int len) {

	/*sr_print_routing_table(sr);*/


	/* check if mimimum packet size satisfied */
	if (len < 21) {
		printf("Not a valid IP packet size (too small)");
		/* TODO: send ICMP error message? */
		return;
	}

	/* calc checksum for IP packet, compare to the checksum included. */
	struct sr_if* iface = sr->if_list;
	sr_ip_hdr_t* ipheader = (sr_ip_hdr_t*) (packet+14);
	sr_ip_hdr_t* h = ipheader;
	printf("Printing IP header data: \t");
	/* printf("%ud, %ud, %ud\n",h->ip_src, h->ip_dst, h->ip_ttl);*/
	print_hdr_ip(ipheader);


	/*printing the packet contents (gee this should be a function shouldn't it)
	int i = 0;
	for (i = 0; i < 20; i++) {
		printf("%02x ", packet[14+i]);
	}
	printf("\n");*/

	uint32_t destIP = ipheader->ip_dst;
	uint32_t srcIP = ipheader->ip_src;
	uint16_t sent_cksum = ipheader->ip_sum;
	uint16_t clearSum = 0x00;
	memcpy(&(ipheader->ip_sum), &clearSum, sizeof(uint16_t)); /*clear out the cksum field before calcing it*/
	int actual_cksum = cksum(packet+14, 20);
	/*TODO: fix checksum calculation (passing wrong parameters potentially)*/
	/*oh we're fucking passing the checksum into the calculation of the checksum*/
	if (actual_cksum != sent_cksum) {
		printf("failed: checksum invalid ");
		printf("%d %d\n",actual_cksum, sent_cksum);
		/*TODO: send ICMP error message?*/
		return;
	}
	/*printf("success: checksum valid ");
	printf("%d %d\n",actual_cksum, sent_cksum);*/

	ipheader->ip_ttl = ipheader->ip_ttl-1;
	ipheader->ip_sum = cksum(packet+14, len-14);



	/* check if any of ethernet interfaces are the destination IP */

	fprintf(stderr, "Checking if packet destined to us, destIP = ");
	print_addr_ip_int(ntohl(destIP));

	while (iface != NULL) {
		printf("looping ifaces\n");
		uint32_t iface_ip = iface->ip;
		print_addr_ip_int(ntohl(iface_ip));

		if(destIP == iface_ip) {

			printf("packet destined for this ethernet interface address: %s, handling packet: ",iface->addr); /*why are we saying ethernet for IP?*/

			/* TODO:handle packet (aka do ICMP ping / traceroute, any TCP/UDP should be met with ICMP port unreachable sent back*/
			/* NO FORWARDING / QUEUEING	IN THIS SECTION*/
			return;
		}

		iface = iface->next;
	}

	/* if forwarding, check routing table (verbatim for now, prefix search later) */

	/* otherwise forward the packet to all other interfaces*/
	struct sr_rt* rt = sr->routing_table;

	/* iterate through all entries in routing table and forward packet to matching IP */
	while (rt != NULL) {
		if (rt->dest.s_addr == (in_addr_t)destIP) {
			/* If we found a match, forward the packet along that interface */
			printf("addr: %d      destip: %d\n\n",rt->dest.s_addr, destIP);

			/* Check if MAC address of next-hop IP is in our cache,
			 * if it is we alter the dest eth addr and send
			 * if not, add this to the arp req queue and move on with our lives*/

			struct sr_arpentry * entry = sr_arpcache_lookup(&(sr->cache),rt->dest.s_addr);

			if (entry == 0) {
				/* if we didn't find it, make like a tree and leave */
				/*appending to queue, arpcache will handle changing the dest MAC addr*/
				sr_arpcache_queuereq(&(sr->cache),rt->dest.s_addr, packet, len, rt->interface);
				printf("~~~~queueing request\n");
				return;
			}

			/* if it is in the arp cache, then update dest MAC and forward*/
			/* TODO: may also need to update source MAC addr to be interface MAC, idk if its that or original src*/
			sr_ethernet_hdr_t* eth_header = (sr_ethernet_hdr_t*)packet;
			memcpy(eth_header->ether_dhost,entry->mac,ETHER_ADDR_LEN);

			/* once packet is properly changed, send it */
			sr_send_packet(sr, packet, len, rt->interface);
			printf("~~~~sent packet with request\n\n");

			print_hdr_arp(packet+14);



			return;
		}

		rt = rt->next;
	}



	iface = sr->if_list;
	/* in event of no IP match in routing table, forward IP packet to all interfaces except for source interface. */
	while (iface != 0) {
		if (iface->ip == srcIP) {
			iface = iface->next;
			continue;
		}
		printf("forwarding packet to iface: %s\n", iface->name);

		sr_send_packet(sr, packet, len, rt->interface);
		iface = iface->next;
	}


	return;
}

void sr_handlepacket(struct sr_instance* sr,
		uint8_t * packet/* lent */,
		unsigned int len,
		char* interface/* lent */)
{
	/* REQUIRES */
	assert(sr);
	assert(packet);
	assert(interface);

	printf("*** -> Received packet of length %d \n",len);

	/*print_hdrs(packet, len);*/

	/* fill in code here */
	/* validate packet: valid checksum, length, and check address */
	if (len < sizeof(sr_ethernet_hdr_t)) {
		printf("length less than length of packet header; malformed packet.\n");
		return;
	}


	/* extract host addr, src addr, eth type from packet */

	sr_ethernet_hdr_t* eth_header = (sr_ethernet_hdr_t*) packet;
	uint8_t* dest_MAC = eth_header->ether_dhost;
	uint8_t* src_MAC = eth_header->ether_shost;
	uint16_t ethtype = eth_header->ether_type;

	sr_ip_hdr_t* eth_data = (sr_ip_hdr_t*) packet+sizeof(sr_ethernet_hdr_t);
	uint32_t dest_IP = eth_data->ip_dst;
	uint32_t src_IP = eth_data->ip_src;
	uint8_t ttl_IP = eth_data->ip_ttl;
	uint16_t cksum_IP = eth_data->ip_sum;

	/*print_addr_ip_int(dest_IP);
  print_addr_ip_int(src_IP);
  printf("ip addresses ^^");*/

	/* classify ethernet frame data as ARP or IP */
	if (ethertype(packet) == ethertype_arp) {
		/* ARP handling */
		printf("Calling handleARPpacket()\n");
		handleARPpacket(sr, interface, packet, len);

	} else if (ethertype(packet) == ethertype_ip) {
		/* IP handling */
		printf("Calling handleIPpacket()\n");
		/*print_addr_ip_int(dest_IP);
		print_addr_ip_int(src_IP);*/

		handleIPpacket(sr, interface, packet, len);

	} else {
		printf("invalid request type\n");
		return;
	}



	/* printf ("%02x :: %02x :: %d",eth_header->ether_dhost[0], eth_header->ether_shost[0], eth_header->ether_type);*/

	/* If the destination address matches this router's IPs, then parse packet further*/


	/* If the destination address doesn't match this router's IPs, then forward packet to other interfaces.  */



}/* end sr_ForwardPacket */

