#include <pthread.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

#define ARP_QUEUE_SIZE 1000 //  dimensione coda 


// struct dell'associazione MAC - IP ricevuta dal receiver.c
typedef struct {
    unsigned char mac_addr[ETH_ALEN];
    struct in_addr ip_addr;
    unsigned char mac_addr_sender[ETH_ALEN];
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

// Dichiarazione della coda come esterna
extern arp_association_queue_t arp_association_queue;

void arp_queue_init(arp_association_queue_t *queue);
void enqueue_arp_association(arp_association_queue_t *queue, arp_association_t association);
arp_association_t *dequeue_arp_association(arp_association_queue_t *queue);
void free_arp_association(arp_association_t *association);