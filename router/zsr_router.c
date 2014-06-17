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
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

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

  sr_arp_hdr_t* arpHdr = (sr_arp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
  sr_ethernet_hdr_t* ethHdr = (sr_ethernet_hdr_t*)packet;
  sr_ip_hdr_t* ipHdr = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
  sr_icmp_hdr_t* icmpHdr = (sr_icmp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

  char* ar_tha = arpHdr->ar_tha;

  printf("if %s\n", interface);

  if(strcmp(ar_tha, "\0") == 0){
    sr_arpcache_queuereq(&(sr->cache), arpHdr->ar_tip, packet, len, interface);
    printf("added arpreq to queue.\n\n");
    return;
  }
  //  printf("arp rep: %d\n", ntohs(arpHdr->ar_op));
  // printf("opcode: %d\n", arp_op_reply);
  if(ntohs(arpHdr->ar_op) == arp_op_reply){
    struct sr_arpentry* ent = sr_arpcache_lookup(&sr->cache, arpHdr->ar_sip);
    if( ent != NULL)
      //      printf("Added %s to cache\n", ntohl(arpHdr->ar_sip));
      sr_arpcache_insert(&(sr->cache), arpHdr->ar_sha, arpHdr->ar_sip);
    //sr_arpcache_dump(&sr->cache);
    free(ent);
    return;
  }


 
  struct sr_rt* rt_walker = 0;

  rt_walker = sr->routing_table;
  char ifBuf[INET_ADDRSTRLEN];
  char* sipBuf = malloc(sizeof(char) * 16);

  inet_ntop(AF_INET, &rt_walker->dest, ifBuf, 100);
      


  /*
    sr_print_routing_entry(rt_walker);
    print_addr_ip(rt_walker->dest);
  */
  //  printf("%s\n", pktBuf);
  convert_addr_ip_int(ntohl(arpHdr->ar_sip), sipBuf);
  printf("Before routing loop\n\n");
  if(strcmp(ifBuf, sipBuf) == 0)
    printf("%s = %s\n",ifBuf, sipBuf);
  while(rt_walker->next)
    {

      

      printf("in loop\n");
      rt_walker = rt_walker->next; 
      inet_ntop(AF_INET, &rt_walker->dest, ifBuf, 100);

      //      printf("if IP: %s\n", ifBuf);
      //printf("hdr DestIP: %s\n", sipBuf);
 
      // if(strcmp(ifBuf,sipBuf) == 0){
      //	printf("%s = %s\n",ifBuf, sipBuf);

      //}
      convert_addr_ip_int(ntohl((ipHdr->ip_dst)), sipBuf);

      //      int boo = 0;
      printf("icmp type = %u\n\n", icmpHdr->icmp_type);
      if(strcmp(ifBuf, sipBuf) == 0){
	if(icmpHdr->icmp_type  == 0){
	  printf("Got a reply packet \n\n");
	}
	struct sr_if* iface = sr_get_interface(sr, rt_walker->interface);
	//sr_arpcache_dump(&sr->cache);
	// Sends out arp_req
	struct sr_arpentry* ent = sr_arpcache_lookup(&sr->cache, ipHdr->ip_dst);
	if(ent != NULL){
	  printf("Entry found: Forwarding to %s\n\n", iface->name);
	  memcpy(ethHdr->ether_shost, (uint8_t*)iface->addr, sizeof(uint8_t) * ETHER_ADDR_LEN);
	  memcpy(ethHdr->ether_dhost, (uint8_t*)ent->mac, sizeof(uint8_t) * ETHER_ADDR_LEN);
	  sr_send_packet(sr, packet, len, iface->name);
	  //sr_arpcache_dump(&sr->cache);
	  //	  wait(1);
	  //	  free(ent);
	}else {
	  //	  if(boo != 0){
	  //	  sr_arpcache_dump(&sr->cache);
	  send_arp_req(sr, rt_walker->interface, sr_get_interface(sr, rt_walker->interface)->addr, iface->ip, ipHdr->ip_dst);
	  // boo++;
	  // }
	}
	free(ent);
	return;
	//	break;
	//memcpy(ethHdr->ether_shost, (uint8_t*)(sr_get_interface(sr, rt_walker->interface)->addr), sizeof(uint8_t) * ETHER_ADDR_LEN);
	
      }
      printf("End routing loop\n\n");
    }

  /*  print_addr_ip_int(ntohl(arpHdr->ar_sip)); */
  /*
  print_hdr_eth(packet);
   print_hdr_icmp(packet);
   sr_print_routing_table(sr);
    sr_print_routing_table(sr);
   print_hdrs(packet, len);
  */

  /* fill in code here */

}/* end sr_ForwardPacket */

//Converts int IP to str
void convert_addr_ip_int(uint32_t ip, char* buf) {
  memset(buf, 0, sizeof(char)*16);
  int pos = 0;
  uint32_t curOctet = ip >> 24;
  pos += sprintf(&buf[pos], "%d.",curOctet);

  curOctet = (ip << 8) >> 24;
  pos += sprintf(&buf[pos], "%d.",curOctet);

  curOctet = (ip << 16) >> 24;
  pos += sprintf(&buf[pos], "%d.",curOctet);
  
  curOctet = (ip << 24) >> 24;
  pos += sprintf(&buf[pos], "%d",curOctet);

  while(pos < 16){
    sprintf(&buf[pos], "\0");
    pos++;
  }
}


//Should convert an unsigned char array of size 12 (12 hex chars in MAC addr)
uint8_t* convert_charAddr_uintAddr(unsigned char* addr){
  uint8_t* ethAddr = (uint8_t*)malloc(sizeof(uint8_t) * 6);

  char* convert = malloc(sizeof(char) * ETHER_ADDR_LEN);
  int i;

  for(i = 0; i < ETHER_ADDR_LEN; i++){
    
    
  }
  for(i = 0; i < ETHER_ADDR_LEN; i++){

    
    
    int hex1, hex2;
    char c1, c2;
    if(isdigit(addr[i]) == 0){
      c1 = addr[i];
      hex1 = c1 - 48;
    }else{
      c1 = (char)toupper(addr[i]);
      hex1 = c1 - 55;
    }

    hex1 = hex1 << 4;
    //printf("%d\n",hex1);

    if(isdigit(addr[i+1]) == 0){
      c2 = addr[i+1];
      hex2 = c2 - 48;
    } else {
      c2 = (char)toupper(addr[i+1]);
      hex2 = c2 - 55;
    }

    hex1 = hex1 | hex2;
    //    char* c2 = (char)toupper(addr[i+1]);
    //int hex2 = *c2 - 48;

    //printf("%X\n",hex1);

    ethAddr[i/2] = hex1;
    
  }
  return ethAddr;

}  
