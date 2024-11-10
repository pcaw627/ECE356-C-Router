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
#include <assert.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

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

  sr_arp_hdr_t* arp_header = (sr_arp_hdr_t*) packet+sizeof(sr_ethernet_hdr_t);


  unsigned short hw_addr = arp_header->ar_hrd;
  uint32_t target_IP = arp_header->ar_tip;

  unsigned short ar_pro = arp_header->ar_hrd;

  struct sr_arpreq* req = sr_arpcache_queuereq(&(sr->cache), target_IP, packet, len, interface);



  /* look up dest IP addr in ARP cache to check if we already know its MAC address. */
  /* sr_arpcache_lookup(sr->cac)*/
  sr_arpcache_sweepreqs(sr);

  /* if in ARP cache, then reply to src MAC addr with the dest MAC addr. */

  /* if NOT in ARP cache, then we want to forward the ARP request to all the other interfaces (except for source). */

  /* */
}

void handleIPpacket(uint8_t* packet) {
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

  print_hdrs(packet, len);

  /* fill in code here */
  /* validate packet: valid checksum, length, and check address */
  if (len < sizeof(sr_ethernet_hdr_t)) {
	  printf("length less than length of packet header; malformed packet.");
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

  /* calc checksum for IP packet, compare to the checksum included. */

  struct sr_if* iface = sr->if_list;

  int forwarding = 1;

  while (iface != 0) {

	  uint32_t eth_ip = iface->ip;

	  if(dest_IP == eth_ip) {
		  forwarding = 0;

		  printf("packet destined for this ethernet interface address: %s, handling packet: ",iface->addr);

		  /* if destination is for this ethernet interface's IP, then handle packet here */
		  if (ethtype == 0x0806) {
			  /* ARP handling */
			  printf("Calling handleARPpacket()\n");
			  handleARPpacket(sr, interface, packet, len);

		  } else if (ethtype == 0x0800) {
			  /* IP handling */
			  print_addr_ip_int(dest_IP);
			  print_addr_ip_int(src_IP);

			  handleIPpacket(packet);

		  } else {
			  printf("invalid request type\n");
			  return;
		  }


	  }

	  iface = iface->next;
  }

  if (forwarding) {
	  /* otherwise forward the packet to all other interfaces */
	  struct sr_if* other_iface = sr->if_list;

	  while (other_iface != 0) {
		  /* if eth IP is the same as src_IP, then continue loop */
		  if (other_iface->ip == src_IP) {
			continue;
		  }

		  /* forward packet */
		  /*printf("forwarding packet to %02X \n", print_addr_ip_int(other_iface->ip));*/
		  print_addr_ip_int(other_iface->ip);
		  print_addr_ip_int(src_IP);
		  printf("\n");

		  other_iface = other_iface->next;
	  }


  }

  /* printf ("%02x :: %02x :: %d",eth_header->ether_dhost[0], eth_header->ether_shost[0], eth_header->ether_type);*/

  /* If the destination address matches this router's IPs, then parse packet further*/


  /* If the destination address doesn't match this router's IPs, then forward packet to other interfaces.  */

  

}/* end sr_ForwardPacket */

