#ifndef ARP_QUEUE_H
#define ARP_QUEUE_H

#include <pthread.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

#define ARP_QUEUE_SIZE 100 // Definisci la dimensione massima della coda ARP

typedef struct {
    unsigned char mac_addr[ETH_ALEN];
    struct in_addr ip_addr;
} arp_association_t;

typedef struct {
    arp_association_t *buffer[ARP_QUEUE_SIZE];
    int head;
    int tail;
    int count;
    pthread_mutex_t mutex;
    pthread_cond_t not_full;
    pthread_cond_t not_empty;
} arp_association_queue_t;

void arp_queue_init(arp_association_queue_t *queue);
void enqueue_arp_association(arp_association_queue_t *queue, arp_association_t association);
arp_association_t *dequeue_arp_association(arp_association_queue_t *queue);
void free_arp_association(arp_association_t *association);

#endif