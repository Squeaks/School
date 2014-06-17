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


    //    printf("TESTING: HOST_UNREACHABLE TYPE: %d CODE: %d\n", ICMP_HOST_UNREACHABLE.type, ICMP_HOST_UNREACHABLE.code);


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
  char eth3Addr[] = "10.0.1.1";
  char eth2Addr[] = "172.64.3.1";
  char eth1Addr[] = "192.168.2.1";
  unsigned char broad[] = "FF:FF:FF:FF:FF:FF";
  //  uint8_t broad[6];
  
  unsigned char* ifMac =  (unsigned char*)malloc(sizeof(unsigned char) * 18);
 
  char* ifAddr = "";
  char empty[] = "";
  int ret = 0;
  /*  
  //  memcpy(&iBroad, (uint8_t)broad, sizeof(uint8_t) * 6);
  memset(broad, 255, sizeof(uint8_t) * 6);
  convert_addr_eth(ethHdr->ether_dhost, ifMac);
  printf("ifMac %s\n", ifMac);
  printf("broad %s\n", broad);
  printf("%u %u\n", ethHdr->ether_dhost, broad);
  print_addr_eth(broad);
  print_addr_eth(ethHdr->ether_dhost);
  printf("%d\n", ethHdr->ether_dhost != broad);
  printf("%s\n", interface);
  print_addr_eth(ifMac);
  printf("%d\n", ethHdr->ether_dhost != ifMac);
  */
  convert_addr_ip_int(ntohl(ipHdr->ip_dst), ipBuf);
  memset(ifBuf, 0, sizeof(char) * 16);

  strcpy(&ifBuf, &eth1Addr);
  ret = strcmp(ifBuf, ipBuf);
  if(ret == 0)
    ifAddr = "eth1";
  
  memset(ifBuf, 0, sizeof(char) * 16);
  strcpy(&ifBuf, &eth2Addr);
  ret = strcmp(ifBuf, ipBuf);
  if(ret == 0)
    ifAddr = "eth2";

  memset(ifBuf, 0, sizeof(char) * 16);
  strcpy(&ifBuf, &eth3Addr);
  ret = strcmp(ifBuf, ipBuf);
  if(ret == 0)
    ifAddr = "eth3";


  if(ntohs(ethHdr->ether_type) != ethertype_arp && ntohs(ethHdr->ether_type) != ethertype_ip){
    printf("Bad packet\n");
    return;
  }
  
  /*
  if(ifMac != ethHdr->ether_dhost && ethHdr->ether_dhost != broad){
    printf("Bad packet\n");
    return;
  }
  */

  if(icmpHdr->icmp_type == 8 && icmpHdr->icmp_code == 0 && strcmp(empty, ifAddr) != 0){
    //    printf("reply to %s\n", ifAddr);
    uint8_t src[6];
    uint32_t ip;
    //    uint8_t dst[6];
    memcpy(&src, ethHdr->ether_shost, sizeof(uint8_t) * 6);
    //    memcpy(&dst, ethHdr->ether_dhost, sizoef(uint8_t) * 6);
    ip = ipHdr->ip_src;
    ipHdr->ip_src = sr_get_interface(sr, interface)->ip;
    ipHdr->ip_dst = ip;
    memcpy(ethHdr->ether_shost, (uint8_t*)(sr_get_interface(sr, route->interface)->addr), sizeof(uint8_t) * ETHER_ADDR_LEN);
    memcpy(ethHdr->ether_dhost, &src, sizeof(uint8_t) * ETHER_ADDR_LEN);
    ipHdr->ip_sum = 0;
    ipHdr->ip_sum = cksum(ipHdr, sizeof(sr_ip_hdr_t));
    icmpHdr->icmp_code = 0;
    icmpHdr->icmp_type = 0;
    icmpHdr->icmp_sum = 0;
    icmpHdr->icmp_sum = cksum(icmpHdr, sizeof(uint8_t) * 64);
    print_hdrs(packet, len);
    sr_send_packet(sr, packet, len, interface);
    //    printf("packet freed\n");
	  //		    send_icmp(sr, pkt->buf, pkt->iface, ICMP_REPLY);
    return;

  }


 
  if(ntohs(ethHdr->ether_type) == ethertype_arp && strcmp(arpHdr->ar_tha, "\0") == 0){
    while(route != NULL){
      inet_ntop(AF_INET, &route->dest, ifBuf, sizeof(char) * INET_ADDRSTRLEN);
      convert_addr_ip_int(ntohl(arpHdr->ar_sip), ipBuf);
      if(strcmp(ifBuf, ipBuf) == 0){
	sr_arpcache_queuereq(&(sr->cache), arpHdr->ar_tip, packet, len, interface);
	//printf("added arpreq to queue.\n\n");
	return;
      }
      route = route->next;
    }
    send_icmp(sr, packet, interface, ICMP_NET_UNREACHABLE);      
    return;
  }
  
  //  printf("arp rep: %d\n", ntohs(arpHdr->ar_op));
  //printf("opcode: %d\n", arp_op_reply);
  if(ntohs(arpHdr->ar_op) == arp_op_reply){
    ent = sr_arpcache_lookup(&sr->cache, arpHdr->ar_sip);
    if( ent == NULL){
      //      printf("Added %s to cache\n", ntohl(arpHdr->ar_sip));
      //      printf("Incoming arp response\n");
      //      sleep(2);
      

      struct sr_arpreq* req = sr->cache.requests;
      //      printf("%p, %p\n", req, sr->cache.requests);
      while(req != NULL){
	if(req->ip == arpHdr->ar_sip){
	  struct sr_packet* pkt = req->packets;
	  route = sr->routing_table;
	  while(pkt != NULL){
	    if(route != NULL){
	      do{
		sr_ip_hdr_t* reqIpHdr = (sr_ip_hdr_t*)(pkt->buf + sizeof(sr_ethernet_hdr_t));
		sr_ethernet_hdr_t* reqEthHdr = (sr_ethernet_hdr_t*)(pkt->buf);
		sr_icmp_hdr_t* reqIcmpHdr = (sr_icmp_hdr_t*)(pkt->buf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
		//      sr_print_routing_entry(route);
		inet_ntop(AF_INET, &route->dest, ifBuf, sizeof(char) * INET_ADDRSTRLEN);
		convert_addr_ip_int(ntohl(reqIpHdr->ip_dst), ipBuf);
		//		printf("%s dest: %s\n",route->interface, ifBuf);
		//printf("ip dest: %s\n", ipBuf);
		if(strcmp(ifBuf, ipBuf) == 0){
		  memset(ifBuf, 0, sizeof(char) * 16);
		  memset(ifBuf, &eth3Addr, sizeof(char) * 8); 
		  //		  ifBuf = "10.0.1.1\0";
		  if(reqIcmpHdr->icmp_type == 8 && reqIcmpHdr->icmp_code == 0 && strcmp(ifBuf, ipBuf) == 0){
		    memcpy(reqEthHdr->ether_shost, (uint8_t*)(sr_get_interface(sr, route->interface)->addr), sizeof(uint8_t) * ETHER_ADDR_LEN);
		    memcpy(reqEthHdr->ether_dhost, (uint8_t*)arpHdr->ar_sha, sizeof(uint8_t) * ETHER_ADDR_LEN);
		    reqIcmpHdr->icmp_code = 0;
		    reqIcmpHdr->icmp_type = 0;
		    reqIcmpHdr->icmp_sum = 0;
		    reqIcmpHdr->icmp_sum = cksum(reqIcmpHdr, sizeof(sr_icmp_hdr_t));
		    sr_send_packet(sr, pkt->buf, pkt->len, &(route->interface));
		    // printf("packet freed\n");
		  //		    send_icmp(sr, pkt->buf, pkt->iface, ICMP_REPLY);
		    break;
		  }
		 
		  memcpy(reqEthHdr->ether_shost, (uint8_t*)(sr_get_interface(sr, route->interface)->addr), sizeof(uint8_t) * ETHER_ADDR_LEN);
		  memcpy(reqEthHdr->ether_dhost, (uint8_t*)arpHdr->ar_sha, sizeof(uint8_t) * ETHER_ADDR_LEN);

		  //		  printf("%u %u %u\n",reqEthHdr->ether_type, ethertype_ip, ethertype_arp);
		  if(reqIpHdr->ip_ttl <= 1){
		    //printf("TTL. Of type: %u Sending icmp error\n", ipHdr->ip_p);
		    send_icmp(sr, pkt->buf, pkt->iface, ICMP_TTL_EXPIRED);
		    printf("TTL expired\n");

		    break;
		  }

		  if(ntohs(reqEthHdr->ether_type) == ethertype_ip){
		    reqIpHdr->ip_ttl -= 1;
		    reqIpHdr->ip_sum = 0;
		    reqIpHdr->ip_sum = cksum(reqIpHdr, sizeof(sr_ip_hdr_t));
		    
		    //		    printf("Dec ttl to %u\n", reqIpHdr->ip_ttl);
		  }
		  //		  print_hdrs(pkt->buf, pkt->len);
		  sr_send_packet(sr, pkt->buf, pkt->len, &(route->interface));
		  printf("pkt sent down %s via req dequeue\n\n", route->interface);
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
	  //	  sr_arpreq_destroy(&sr->cache, req);
	  break;
	}
	req = req->next;
      }

    }
    sr_arpcache_insert(&(sr->cache), arpHdr->ar_sha, arpHdr->ar_sip);  

    fprintf(stderr, "\nAdded entry to ARP cache\n");
    print_addr_eth(ethHdr->ether_dhost);
    print_addr_ip_int(ntohl(arpHdr->ar_tip));
    fprintf(stderr, "\n");
    
    //sr_arpcache_dump(&sr->cache);
    free(ent);
    return;
  }

  convert_addr_ip_int(ntohl(ipHdr->ip_dst), ipBuf);
  memset(ifBuf, 0, sizeof(char) * 16);
  memset(ifBuf, &eth3Addr, sizeof(char) * 8); 
		  

  if(icmpHdr->icmp_type == 8 && icmpHdr->icmp_code == 0 && strcmp(ifBuf, ipBuf) == 0){
    uint8_t temp[6];
    memcpy(&temp, ethHdr->ether_shost, sizeof(uint8_t) * 6);
    memcpy(ethHdr->ether_shost, (uint8_t*)(sr_get_interface(sr, route->interface)->addr), sizeof(uint8_t) * ETHER_ADDR_LEN);
    memcpy(ethHdr->ether_dhost, &temp, sizeof(uint8_t) * ETHER_ADDR_LEN);
    icmpHdr->icmp_code = 0;
    icmpHdr->icmp_type = 0;
    icmpHdr->icmp_sum = 0;
    icmpHdr->icmp_sum = cksum(icmpHdr, sizeof(sr_icmp_hdr_t));
    sr_send_packet(sr, packet, len, interface);
    //    printf("packet freed\n");
	  //		    send_icmp(sr, pkt->buf, pkt->iface, ICMP_REPLY);
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
    send_icmp(sr, packet, interface, ICMP_NET_UNREACHABLE);      
    return;
    }
  }
  
  //  printf("ip proto: %u\n", ipHdr->ip_p);
  /*
  printf("ip proto ntohs: %u\n", ntohs(ipHdr->ip_p));
  printf("icmp proto: %u\n", ip_protocol_icmp);
  */

  /*  
  if(ipHdr->ip_p == 17 || ipHdr->ip_p == 6){
    printf("not icmp. Sending icmp error\n");
    send_icmp(sr, packet, interface, ICMP_PORT_UNREACHABLE);
    //free(ent);
    // return;
  }
  */
  //Forwards packet to interface
  if(route != NULL){
    do{
      //      sr_print_routing_entry(route);
      inet_ntop(AF_INET, &route->dest, ifBuf, sizeof(char) * INET_ADDRSTRLEN);
      convert_addr_ip_int(ntohl(ipHdr->ip_dst), ipBuf);
      //  printf("%s dest: %s\n",route->interface, ifBuf);
      //printf("ip dest: %s\n", ipBuf);
      if(strcmp(ifBuf, ipBuf) == 0){
	
	memcpy(ethHdr->ether_shost, (uint8_t*)(sr_get_interface(sr, route->interface)->addr), sizeof(uint8_t) * ETHER_ADDR_LEN);
	memcpy(ethHdr->ether_dhost, (uint8_t*)ent->mac, sizeof(uint8_t) * ETHER_ADDR_LEN);
	//printf("%u\n", ethHdr->ether_type);

	//	convert_addr_ip_int(ntohl(reqIpHdr->ip_dst), ipBuf);

	memset(ifBuf, 0, sizeof(char) * 16);
	memset(ifBuf, &eth3Addr, sizeof(char) * 8); 
 

	if(icmpHdr->icmp_type == 8 && icmpHdr->icmp_code == 0 && strcmp(ifBuf, ipBuf) == 0){
	  uint8_t temp[6];
	  memcpy(&temp, ethHdr->ether_shost, sizeof(uint8_t) * 6);
	  memcpy(ethHdr->ether_shost, (uint8_t*)(sr_get_interface(sr, route->interface)->addr), sizeof(uint8_t) * ETHER_ADDR_LEN);
	  memcpy(ethHdr->ether_dhost, &temp, sizeof(uint8_t) * ETHER_ADDR_LEN);
	  icmpHdr->icmp_code = 0;
	  icmpHdr->icmp_type = 0;
	  icmpHdr->icmp_sum = 0;
	  icmpHdr->icmp_sum = cksum(icmpHdr, sizeof(sr_icmp_hdr_t));
	  sr_send_packet(sr, packet, len, interface);
	  //printf("packet freed\n");
	  //		    send_icmp(sr, pkt->buf, pkt->iface, ICMP_REPLY);
	  return;
	}


	/*
	if(icmpHdr->icmp_type == 8 && icmpHdr->icmp_code == 0){
	  send_icmp(sr, packet, interface, ICMP_REPLY);
	  free(ent);
	  return;
	}
	*/
	if(ipHdr->ip_ttl <= 1){
	  send_icmp(sr, packet, interface, ICMP_TTL_EXPIRED);
	  printf("TTL expired\n");
	  free(ent);
	  return;
	}


	if(ntohs(ethHdr->ether_type) == ethertype_ip){
	  ipHdr->ip_ttl -= 1;
	  ipHdr->ip_sum = 0;
	  ipHdr->ip_sum = cksum(ipHdr, sizeof(sr_ip_hdr_t));
	  //	  printf("Dec ttl to %u\n", ipHdr->ip_ttl);
	}
	//	print_hdrs(packet, len);
	sr_send_packet(sr, packet, len, &(route->interface));
	printf("pkt sent down %s via forwarding\n\n", route->interface);
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


void send_icmp_error(struct sr_instance *sr, uint8_t *pkt, char *iface, struct __err_icmp_t msg){
  printf("trying to send ICMP error\n");
  printf("Sending icmp type %d, code %d\n", msg.type, msg.code);

  int len = (sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));

  uint8_t *response = (uint8_t*)malloc(len);

  memcpy(response, pkt, len);

  sr_ethernet_hdr_t *ethHdr = (sr_ethernet_hdr_t*)response;
  sr_ip_hdr_t *ipHdr = (sr_ip_hdr_t*)(response + sizeof(sr_ethernet_hdr_t));
  sr_icmp_t3_hdr_t *icmpHdr = (sr_icmp_t3_hdr_t*)(response + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

  //printf("1\n");
  //Swap ether header
  uint8_t temp[6];
  memcpy(&temp, ethHdr->ether_dhost, sizeof(uint8_t) * ETHER_ADDR_LEN);
  //  uint16_t* ether = ethertype_ip;
  memcpy(ethHdr->ether_dhost, ethHdr->ether_shost, sizeof(uint8_t) * ETHER_ADDR_LEN);
  memcpy(ethHdr->ether_shost, &temp, sizeof(uint8_t) * ETHER_ADDR_LEN);
  ethHdr->ether_type = htons(ethertype_ip);
  

  (*icmpHdr).icmp_type = msg.type;
  (*icmpHdr).icmp_code = msg.code;
  
  //uint32_t tempIP = ipHdr->ip_dst;
  (*ipHdr).ip_dst = (*ipHdr).ip_src;
  //ipHdr->ip_src = tempIP;
  ipHdr->ip_src = sr_get_interface(sr, iface)->ip;
  //ipHdr->ip_ttl -= 1;
  ipHdr->ip_hl = 5;
  ipHdr->ip_v = 4;
  ipHdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
  ipHdr->ip_ttl = 64;
  ipHdr->ip_p = ip_protocol_icmp;
  icmpHdr->icmp_sum = 0;
  ipHdr->ip_sum = 0;
  ipHdr->ip_sum = cksum(ipHdr, sizeof(sr_ip_hdr_t));
  memcpy(icmpHdr->data, (uint8_t*)ipHdr, sizeof(uint8_t) * ICMP_DATA_SIZE);
  (*icmpHdr).icmp_sum = cksum(icmpHdr, sizeof(sr_icmp_t3_hdr_t));
  //  fprintf(stderr,"%u\n", sizeof(sr_icmp_t3_hdr_t));
  //  print_hdrs(response, len);
  printf("Sending icmp response down %s\n", iface);
  sr_send_packet(sr, response, len, iface);

}


void send_icmp(struct sr_instance *sr, uint8_t *pkt, char *iface, struct __err_icmp_t msg){
  printf("Sending type %d code %d\n", msg.type, msg.code);
  int len;
  if(msg.type == 0)
    len = (sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t));
  else 
    len = (sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));

 uint8_t *response = (uint8_t*)malloc(len);

  sr_ethernet_hdr_t* ethHdr = (sr_ethernet_hdr_t*)response;
  sr_ip_hdr_t *ipHdr = (sr_ip_hdr_t*)(response + sizeof(sr_ethernet_hdr_t));
  sr_icmp_t3_hdr_t* icmpHdr = (sr_icmp_t3_hdr_t*)(response + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

  sr_icmp_hdr_t* stdIcmpHdr = (sr_icmp_hdr_t*)(response + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

  sr_ethernet_hdr_t* pktEthHdr = (sr_ethernet_hdr_t*)pkt;
  sr_ip_hdr_t* pktIpHdr = (sr_ip_hdr_t*)(pkt + sizeof(sr_ethernet_hdr_t));
  sr_icmp_hdr_t* pktIcmpHdr = (sr_icmp_hdr_t*)(pkt + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
  //  sr_icmp_t3_hdr_t* pktIcmpHdr = (sr_icmp_t3_hdr_t*)(response + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

  int type0 = 0;

  //  if(type0 == 1){
    char ifBuf[INET_ADDRSTRLEN];
    char ipBuf[INET_ADDRSTRLEN];
    char* interface = "";
    struct sr_rt* route = sr->routing_table;
    
    while(route != NULL){
      inet_ntop(AF_INET, &route->dest, ifBuf, sizeof(char) * INET_ADDRSTRLEN);
      convert_addr_ip_int(ntohl(pktIpHdr->ip_src), ipBuf);
      //      printf("%s dest: %s\n",route->interface, ifBuf);
      //      printf("ip dest: %s\n", ipBuf);
      if(strcmp(ifBuf, ipBuf) == 0){
	//	interface = route->interface;
	break;
      }
      route = route->next;
    }
    int notFound = 0;
    struct sr_arpentry* entry = sr_arpcache_lookup(&sr->cache, pktIpHdr->ip_src);
    if(entry == NULL){
      
      notFound = 1;
      
    printf("arp lookup not in cache. ICMP not sent\n");
    
    }
    //    sr_print_routing_entry(route);
    //sr_print_if(sr_get_interface(sr, route->interface));
    if(notFound == 1)
      memcpy(ethHdr->ether_dhost, pktEthHdr->ether_shost, sizeof(uint8_t) * ETHER_ADDR_LEN);
    else
      memcpy(ethHdr->ether_dhost, entry->mac, sizeof(uint8_t) * ETHER_ADDR_LEN);
    
    // memcpy(ethHdr->ether_shost, sr_get_interface(sr, iface)->addr, sizeof(uint8_t) * ETHER_ADDR_LEN);
    memcpy(ethHdr->ether_shost, &sr_get_interface(sr,route->interface)->addr, sizeof(uint8_t) * ETHER_ADDR_LEN);
    
    //  ethHdr->ether_shost = sr_get_interface(sr, iface)->addr;
    ethHdr->ether_type = htons(ethertype_ip);
    
    ipHdr->ip_v = 4;
    ipHdr->ip_hl = 5;
    ipHdr->ip_tos = 0;
    ipHdr->ip_len = htons(len - sizeof(uint8_t) * 14);
    if(msg.type == 0)
      ipHdr->ip_id = pktIpHdr->ip_id;
    else
      ipHdr->ip_id = 0;
    ipHdr->ip_off = 0;
    ipHdr->ip_ttl = 100;
    ipHdr->ip_p = ip_protocol_icmp;
    ipHdr->ip_sum = 0;
    //  ipHdr->ip_src = sr_get_interface(sr, iface)->ip;
    ipHdr->ip_src = sr_get_interface(sr, route->interface)->ip;
    ipHdr->ip_dst = pktIpHdr->ip_src;
    ipHdr->ip_sum = cksum(ipHdr, sizeof(sr_ip_hdr_t));
    //    printf("msg %d\n", msg.type);

    icmpHdr->icmp_type = msg.type;
    icmpHdr->icmp_code = msg.code;
    icmpHdr->unused = 0;
    icmpHdr->next_mtu = 0;
    memcpy(icmpHdr->data, (uint8_t*)pktIpHdr, sizeof(uint8_t) * ICMP_DATA_SIZE);
    icmpHdr->icmp_sum = cksum(icmpHdr, sizeof(sr_icmp_t3_hdr_t));

  if(notFound == 1){
    sr_arpcache_queuereq(&(sr->cache), pktIpHdr->ip_src, response, len, route->interface);
    printf("icmp packet not sent. ARP req queued\n");
    return;
  }
  //  fprintf(stderr, "pkt came from: ");
  //  print_addr_ip_int(ntohl(pktIpHdr->ip_src));

  //fprintf(stderr, "pkt sent down to: ");
  //print_addr_ip_int(ntohl(ipHdr->ip_src));
  //printf("inc pkt\n");
  //print_hdrs(pkt, len);
  //printf("out pkt\n");
  //print_hdrs(response, len);
  //printf("icmp sent down %s\n", route->interface);
  sr_send_packet(sr, response, len, route->interface);

}

void convert_addr_eth(uint8_t *addr, unsigned char* arr) {
  int pos = 0;
  uint8_t cur;
  for (; pos < ETHER_ADDR_LEN; pos++) {
    cur = addr[pos];
    if (pos > 0)
      sprintf(&arr[pos], ":");
    sprintf(&arr[pos], "%02X", cur);
  }
  fprintf("%02X", arr);
  fprintf(stderr, "\n");
  /*
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
  */

}
