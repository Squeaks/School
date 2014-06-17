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


    printf("TESTING: HOST_UNREACHABLE TYPE: %d CODE: %d\n", ICMP_HOST_UNREACHABLE.type, ICMP_HOST_UNREACHABLE.code);


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
 

  struct sr_rt* route = sr->routing_table;
  struct sr_arpentry* ent;
  char ifBuf[INET_ADDRSTRLEN];
  char ipBuf[INET_ADDRSTRLEN];



  if(strcmp(arpHdr->ar_tha, "\0") == 0){
    sr_arpcache_queuereq(&(sr->cache), arpHdr->ar_tip, packet, len, interface);
    printf("added arpreq to queue.\n\n");
    return;
  }
  printf("arp rep: %d\n", ntohs(arpHdr->ar_op));
  printf("opcode: %d\n", arp_op_reply);
  if(ntohs(arpHdr->ar_op) == arp_op_reply){
    ent = sr_arpcache_lookup(&sr->cache, arpHdr->ar_sip);
    if( ent == NULL){
      //      printf("Added %s to cache\n", ntohl(arpHdr->ar_sip));
      printf("Incoming arp response\n");
      //      sleep(2);
      

      struct sr_arpreq* req = sr->cache.requests;
      printf("%p, %p\n", req, sr->cache.requests);
      while(req != NULL){
	if(req->ip == arpHdr->ar_sip){
	  struct sr_packet* pkt = req->packets;
	  while(pkt != NULL){
	    if(route != NULL){
	      do{
		sr_ip_hdr_t* reqIpHdr = (sr_ip_hdr_t*)(pkt->buf + sizeof(sr_ethernet_hdr_t));
		sr_ethernet_hdr_t* reqEthHdr = (sr_ethernet_hdr_t*)(pkt->buf);
		//      sr_print_routing_entry(route);
		inet_ntop(AF_INET, &route->dest, ifBuf, sizeof(char) * INET_ADDRSTRLEN);
		convert_addr_ip_int(ntohl(reqIpHdr->ip_dst), ipBuf);
		printf("%s dest: %s\n",route->interface, ifBuf);
		printf("ip dest: %s\n", ipBuf);
		if(strcmp(ifBuf, ipBuf) == 0){
		  
		  memcpy(reqEthHdr->ether_shost, (uint8_t*)(sr_get_interface(sr, route->interface)->addr), sizeof(uint8_t) * ETHER_ADDR_LEN);
		  memcpy(reqEthHdr->ether_dhost, (uint8_t*)arpHdr->ar_sha, sizeof(uint8_t) * ETHER_ADDR_LEN);
		  print_hdrs(pkt->buf, pkt->len);
		  sr_send_packet(sr, pkt->buf, pkt->len, &(route->interface));
		  printf("pkt sent down %s\n\n", route->interface);
		  //	  free(ent);
		  //return;
		  break;
		}
		route = route->next;
	      } while(route != NULL);
	      pkt = pkt->next;
	    }

	  }
	  free(ent);
	  sr_arpreq_destroy(&sr->cache, req);
	  break;
	}
	req = req->next;
      }

    }
    sr_arpcache_insert(&(sr->cache), arpHdr->ar_sha, arpHdr->ar_sip);  




    //sr_arpcache_dump(&sr->cache);
    free(ent);
    return;
  }

  ent = sr_arpcache_lookup(&sr->cache, ipHdr->ip_dst);
  route = sr->routing_table;
  //Make and queue requests if dest isn't in arpcache
  if( ent == NULL ){
    if(route != NULL){
      do{
	inet_ntop(AF_INET, &route->dest, ifBuf, 100);
	convert_addr_ip_int(ntohl(ipHdr->ip_dst), ipBuf);
	if(strcmp(ifBuf, ipBuf) == 0){
	  sr_arpcache_queuereq(&sr->cache, ipHdr->ip_dst, packet, len, route->interface);
	  free(ent);
	  return;
	}
	route = route->next;
      } while(route != NULL);
      sr_arpcache_queuereq(&sr->cache, ipHdr->ip_dst, packet, len, "eth1");

    }
  }

  //Forwards packet to interface
  if(route != NULL){
    do{
      //      sr_print_routing_entry(route);
      inet_ntop(AF_INET, &route->dest, ifBuf, sizeof(char) * INET_ADDRSTRLEN);
      convert_addr_ip_int(ntohl(ipHdr->ip_dst), ipBuf);
      printf("%s dest: %s\n",route->interface, ifBuf);
      printf("ip dest: %s\n", ipBuf);
      if(strcmp(ifBuf, ipBuf) == 0){
	
	memcpy(ethHdr->ether_shost, (uint8_t*)(sr_get_interface(sr, route->interface)->addr), sizeof(uint8_t) * ETHER_ADDR_LEN);
	memcpy(ethHdr->ether_dhost, (uint8_t*)ent->mac, sizeof(uint8_t) * ETHER_ADDR_LEN);
	print_hdrs(packet, len);
	sr_send_packet(sr, packet, len, &(route->interface));
	printf("pkt sent down %s\n\n", route->interface);
	free(ent);
	return;
      }
      route = route->next;
    } while(route != NULL);
  }

  free(ent);
  


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

void send_icmp_error(struct sr_instance *sr, uint8_t *pkt, char *iface, struct __err_icmp_t msg){
  printf("trying to send ICMP error\n");

  uint8_t *response = (uint8_t*)malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t));
  sr_ethernet_hdr_t *ethHdr = (sr_ethernet_hdr_t*)response;
  sr_ip_hdr_t *ipHdr = (sr_ip_hdr_t*)(response + sizeof(sr_ethernet_hdr_t));
  sr_icmp_hdr_t *icmpHdr = (sr_icmp_hdr_t*)(response + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

  memcpy(response, pkt, sizeof(response));

  //Swap ether header
  uint8_t* temp = ethHdr->ether_dhost;
  memcpy(ethHdr->ether_dhost, ethHdr->ether_shost, sizeof(uint8_t) * ETHER_ADDR_LEN);
  memcpy(ethHdr->ether_shost, &temp, sizeof(uint8_t) * ETHER_ADDR_LEN);

  (*icmpHdr).icmp_type = msg.type;
  (*icmpHdr).icmp_code = msg.code;
  (*icmpHdr).icmp_sum = cksum(icmpHdr, sizeof(sr_icmp_hdr_t));

  (*ipHdr).ip_dst = (*ipHdr).ip_src;

  sr_send_packet(sr, response, sizeof(response), iface);

}
