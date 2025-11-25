#ifndef ARP_QUEUE_H
#define ARP_QUEUE_H
#include <pthread.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <time.h> // Necessario per struct timespec

// #define ARP_QUEUE_SIZE 1000 //  dimensione coda 
// #define ARP_QUEUE_SIZE 10000 //  dimensione coda x10 per testing
#define ARP_QUEUE_SIZE 2500 //  dimensione coda x10 per testing


// struct dell'associazione MAC - IP ricevuta dal receiver.c
typedef struct {
    unsigned char mac_addr[ETH_ALEN];
    struct in_addr ip_addr;
    unsigned char mac_addr_sender[ETH_ALEN];
    struct timespec reception_time; // time di ricezione
} arp_association_t;

// struct per le metriche di misurazione
typedef struct {
    unsigned long total_processed;  // tot pacchetti analizzati
    unsigned long attacks_detected; // tot attacchi
    double total_latency_accum;     // sum delle latenze (per la media)
    pthread_mutex_t mutex;          // mtex per proteggere la struct
} dai_metrics_t;

typedef struct {
    arp_association_t *buffer[ARP_QUEUE_SIZE];
    int head;
    int tail;
    int count;
    pthread_mutex_t mutex;
    pthread_cond_t not_full;
    pthread_cond_t not_empty;
    pthread_mutex_t *stdout_mutex;
    int peak_count; // memorizza il massimo count raggiunto per metrics
} arp_association_queue_t;

// Dichiarazione della coda come esterna
// extern arp_association_queue_t arp_association_queue;

void arp_queue_init(arp_association_queue_t *queue, pthread_mutex_t *stdout_mutex);
void enqueue_arp_association(arp_association_queue_t *queue, arp_association_t association);
arp_association_t *dequeue_arp_association(arp_association_queue_t *queue);
void free_arp_association(arp_association_t *association);
void list_arp_association(arp_association_queue_t *queue);
char *mac_to_str(const unsigned char *mac_addr, char *mac_str);
#endif 