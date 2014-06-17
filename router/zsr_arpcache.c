#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <string.h>
#include "sr_arpcache.h"
#include "sr_router.h"
#include "sr_if.h"
#include "sr_protocol.h"
#include "sr_utils.h"

/* 
  This function gets called every second. For each request sent out, we keep
  checking whether we should resend an request or destroy the arp request.
  See the comments in the header file for an idea of what it should look like.
*/



void sr_arpcache_sweepreqs(struct sr_instance *sr) { 
    /* Fill this in */
  struct sr_arpreq* req = sr->cache.requests;
  struct sr_arpreq* nextReq = req;

 

  if(nextReq != NULL){
    req = nextReq;
    sr_ethernet_hdr_t* ethHdr =(sr_ethernet_hdr_t*)req->packets->buf;
    sr_arp_hdr_t* arpHdr = (sr_arp_hdr_t*)(req->packets->buf + sizeof(sr_ethernet_hdr_t));
    if(arpHdr->arp_op == ntohs(arp_op_req)){
      create_arp_response(req, sr);
    } else {
      send_arp_req(sr, req->packets->iface, sr_get_interface(req->packets->iface)->addr, arpHdr->ar_tip, arpHdr->ar_sip);
    printf("Modified pkt \n\n");
    print_hdrs(req->packets->buf, req->packets->len);
    printf("End modified pkt \n\n");
    
    //    sr_send_packet(sr, req->packets->buf, req->packets->len, req->packets->iface);
    
    nextReq = req->next;
    
    sr_arpreq_destroy(&(sr->cache), req);
    //    sr_ethernet_hdr_t* ethHdr = (sr_ethernet_hdr_t*)malloc(sizeof(sr_ethernet_hdr_t)); //+ sizeof(struct sr_arp_hdr_t));
    //    struct sr_ethernet_hdr_t* ethHdr = (sr_ethernet_hdr_t*)packet;
    //   sr_arp_hdr_t* arpHdr = (req->packets->buf + sizeof(sr_ethernet_hdr_t));
    //    ethHdr->ether_dhost = convert_charAddr_uintAddr((((sr_arp_hdr_t*)req->packets->buf)->ar_sha), sr_get_interface(sr, req->packets->iface)->addr);
    // uint8_t* dest = convert_charAddr_uintAddr(arpHdr->ar_sha);
    //uint8_t dhost[6];
    //memcpy(dhost, dest, sizeof(uint8_t) * 6);
    //ethHdr->ether_dhost = &dhost;

    
    // print_hdr_eth((uint8_t*)ethHdr);
    //    ((sr_ethernet_hdr_t*)req->packets->buf)->ether_shost = sr_get_interface(sr, req->packets->iface)->addr;
    //sr_send_packet(sr, req->packets->buf, req->packets->len, req->packets->iface);
    //req->times_sent++;
  }
}

void create_arp_response(struct sr_arpreq* req, struct sr_instance* sr){
  struct sr_packet* pkt = req->packets;
  struct sr_if* addr = sr_get_interface(sr, pkt->iface);
  
  uint8_t*  cast = (uint8_t*)addr->addr;
  //uint8_t* ifaceAddr = convert_charAddr_uintAddr(sr_get_interface(sr, pkt->iface)->addr);

  sr_ethernet_hdr_t* ethHdr =(sr_ethernet_hdr_t*)pkt->buf;
  sr_arp_hdr_t* arpHdr = (sr_arp_hdr_t*)(pkt->buf + sizeof(sr_ethernet_hdr_t));
  
  //  uint8_t* dhost = ethHdr->ether_shost
  //  ethHdr->ether_dhost = (*(ethHdr->ether_shost));
  memcpy(ethHdr->ether_dhost, ethHdr->ether_shost, sizeof(uint8_t) * 6);
  memcpy(ethHdr->ether_shost, cast, sizeof(uint8_t) * 6);
  //free(ifaceAddr);

  memcpy(arpHdr->ar_tha, arpHdr->ar_sha, sizeof(unsigned char) * ETHER_ADDR_LEN);
  memcpy(arpHdr->ar_sha, sr_get_interface(sr, pkt->iface)->addr, sizeof(unsigned char) * ETHER_ADDR_LEN);
  
  uint32_t tempIP = arpHdr->ar_sip;
  
  //  memcpy(arpHdr->ar_sip, arpHdr->ar_tip, sizeof(uint32_t));
  //memcpy(arpHdr->ar_tip, tempIP, sizeof(uint32_t));
  arpHdr->ar_sip = arpHdr->ar_tip;
  arpHdr->ar_tip = tempIP;
  arpHdr->ar_op = htons((unsigned short)2); //sets reply opcode

  sr_arpcache_insert(&(sr->cache), arpHdr->ar_tha, arpHdr->ar_tip);
  
}

int send_arp_req(struct sr_instance* sr, char* iface, unsigned char* sha, uint32_t sip, uint32_t tip ){
  uint8_t* packet = (uint8_t*)malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
  
  sr_ethernet_hdr_t* ethHdr = (sr_ethernet_hdr_t*)packet;
  sr_arp_hdr_t* arpHdr = (sr_arp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));

  uint8_t* srcAddr = (uint8_t*)(sr_get_interface(sr, iface)->addr);
  
  //Set src and dest fields (dest to broadcast)
  memcpy(ethHdr->ether_shost, srcAddr, sizeof(uint8_t) * ETHER_ADDR_LEN);
  memset(ethHdr->ether_dhost, 255, sizeof(uint8_t) * ETHER_ADDR_LEN);
  ethHdr->ether_type = htons(ethertype_arp);

  //Set arp headers
  arpHdr->ar_hrd = htons(1);
  arpHdr->ar_pro = htons(2048);
  arpHdr->ar_hln = 6;
  arpHdr->ar_pln = 4; 
  arpHdr->ar_op = htons(1); //request
  memcpy(arpHdr->ar_sha, sha, sizeof(unsigned char) * ETHER_ADDR_LEN);
  arpHdr->ar_sip =sip;
  memset(arpHdr->ar_tha, 0, sizeof(uint8_t) * ETHER_ADDR_LEN);
  arpHdr->ar_tip = tip;

  sr_send_packet(sr, packet, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t), iface);

  return 0;
}



// void?
void sr_handle_arpreq(req){
  /*
    if difftime(now, req->sent) > 1.0 
      if req->times_sent >= 5:
        send icmp host unreachable to source addr of all pkts waiting on this request 
        arpreq_destroy(req)
      else: 
        send arp request  
        req->sent = now   
        req->times_sent++  
  */
}
/* You should not need to touch the rest of this code. */

/* Checks if an IP->MAC mapping is in the cache. IP is in network byte order.
   You must free the returned structure if it is not NULL. */
struct sr_arpentry *sr_arpcache_lookup(struct sr_arpcache *cache, uint32_t ip) {
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpentry *entry = NULL, *copy = NULL;
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if ((cache->entries[i].valid) && (cache->entries[i].ip == ip)) {
            entry = &(cache->entries[i]);
        }
    }
    
    /* Must return a copy b/c another thread could jump in and modify
       table after we return. */
    if (entry) {
        copy = (struct sr_arpentry *) malloc(sizeof(struct sr_arpentry));
        memcpy(copy, entry, sizeof(struct sr_arpentry));
    }
        
    pthread_mutex_unlock(&(cache->lock));
    
    return copy;
}

/* Adds an ARP request to the ARP request queue. If the request is already on
   the queue, adds the packet to the linked list of packets for this sr_arpreq
   that corresponds to this ARP request. You should free the passed *packet.
   
   A pointer to the ARP request is returned; it should not be freed. The caller
   can remove the ARP request from the queue by calling sr_arpreq_destroy. */
struct sr_arpreq *sr_arpcache_queuereq(struct sr_arpcache *cache,
                                       uint32_t ip,
                                       uint8_t *packet,           /* borrowed */
                                       unsigned int packet_len,
                                       char *iface)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req;
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {
            break;
        }
    }
    
    /* If the IP wasn't found, add it */
    if (!req) {
        req = (struct sr_arpreq *) calloc(1, sizeof(struct sr_arpreq));
        req->ip = ip;
        req->next = cache->requests;
        cache->requests = req;
    }
    
    /* Add the packet to the list of packets for this request */
    if (packet && packet_len && iface) {
      struct sr_packet *new_pkt = (struct sr_packet *)malloc(sizeof(struct sr_packet));
      
      new_pkt->buf = (uint8_t *)malloc(packet_len);
      memcpy(new_pkt->buf, packet, packet_len);
      new_pkt->len = packet_len;
      new_pkt->iface = (char *)malloc(sr_IFACE_NAMELEN);
      strncpy(new_pkt->iface, iface, sr_IFACE_NAMELEN);
      new_pkt->next = req->packets;
      req->packets = new_pkt;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* This method performs two functions:
   1) Looks up this IP in the request queue. If it is found, returns a pointer
      to the sr_arpreq with this IP. Otherwise, returns NULL.
   2) Inserts this IP to MAC mapping in the cache, and marks it valid. */
struct sr_arpreq *sr_arpcache_insert(struct sr_arpcache *cache,
                                     unsigned char *mac,
                                     uint32_t ip)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req, *prev = NULL, *next = NULL; 
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {            
            if (prev) {
                next = req->next;
                prev->next = next;
            } 
            else {
                next = req->next;
                cache->requests = next;
            }
            
            break;
        }
        prev = req;
    }
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if (!(cache->entries[i].valid))
            break;
    }
    
    if (i != SR_ARPCACHE_SZ) {
        memcpy(cache->entries[i].mac, mac, 6);
        cache->entries[i].ip = ip;
        cache->entries[i].added = time(NULL);
        cache->entries[i].valid = 1;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* Frees all memory associated with this arp request entry. If this arp request
   entry is on the arp request queue, it is removed from the queue. */
void sr_arpreq_destroy(struct sr_arpcache *cache, struct sr_arpreq *entry) {
    pthread_mutex_lock(&(cache->lock));
    
    if (entry) {
        struct sr_arpreq *req, *prev = NULL, *next = NULL; 
        for (req = cache->requests; req != NULL; req = req->next) {
            if (req == entry) {                
                if (prev) {
                    next = req->next;
                    prev->next = next;
                } 
                else {
                    next = req->next;
                    cache->requests = next;
                }
                
                break;
            }
            prev = req;
        }
        
        struct sr_packet *pkt, *nxt;
        
        for (pkt = entry->packets; pkt; pkt = nxt) {
            nxt = pkt->next;
            if (pkt->buf)
                free(pkt->buf);
            if (pkt->iface)
                free(pkt->iface);
            free(pkt);
        }
        
        free(entry);
    }
    
    pthread_mutex_unlock(&(cache->lock));
}

/* Prints out the ARP table. */
void sr_arpcache_dump(struct sr_arpcache *cache) {
    fprintf(stderr, "\nMAC            IP         ADDED                      VALID\n");
    fprintf(stderr, "-----------------------------------------------------------\n");
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        struct sr_arpentry *cur = &(cache->entries[i]);
        unsigned char *mac = cur->mac;
        fprintf(stderr, "%.1x%.1x%.1x%.1x%.1x%.1x   %.8x   %.24s   %d\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ntohl(cur->ip), ctime(&(cur->added)), cur->valid);
    }
    
    fprintf(stderr, "\n");
}

/* Initialize table + table lock. Returns 0 on success. */
int sr_arpcache_init(struct sr_arpcache *cache) {  
    /* Seed RNG to kick out a random entry if all entries full. */
    srand(time(NULL));
    
    /* Invalidate all entries */
    memset(cache->entries, 0, sizeof(cache->entries));
    cache->requests = NULL;
    
    /* Acquire mutex lock */
    pthread_mutexattr_init(&(cache->attr));
    pthread_mutexattr_settype(&(cache->attr), PTHREAD_MUTEX_RECURSIVE);
    int success = pthread_mutex_init(&(cache->lock), &(cache->attr));
    
    return success;
}

/* Destroys table + table lock. Returns 0 on success. */
int sr_arpcache_destroy(struct sr_arpcache *cache) {
    return pthread_mutex_destroy(&(cache->lock)) && pthread_mutexattr_destroy(&(cache->attr));
}

/* Thread which sweeps through the cache and invalidates entries that were added
   more than SR_ARPCACHE_TO seconds ago. */
void *sr_arpcache_timeout(void *sr_ptr) {
    struct sr_instance *sr = sr_ptr;
    struct sr_arpcache *cache = &(sr->cache);
    
    while (1) {
        sleep(1.0);
        
        pthread_mutex_lock(&(cache->lock));
    
        time_t curtime = time(NULL);
        
        int i;    
        for (i = 0; i < SR_ARPCACHE_SZ; i++) {
            if ((cache->entries[i].valid) && (difftime(curtime,cache->entries[i].added) > SR_ARPCACHE_TO)) {
                cache->entries[i].valid = 0;
            }
        }
        
        sr_arpcache_sweepreqs(sr);

        pthread_mutex_unlock(&(cache->lock));
    }
    
    return NULL;
}

