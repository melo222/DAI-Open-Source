#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include "arp_queue.h"

// coda condivisa di associazioni ARP 
arp_association_queue_t arp_queue;

// funzione per avviare ogni thread ricevitore ARP
pthread_t start_receiver_thread(const char *iface_name);

// funzione per avviare il pool di thread analizzatori di ARP
void start_arp_analyzer_pool(int num_threads);

// mutex per la gestione concorrente di stdout
pthread_mutex_t stdout_mutex;

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Uso: %s <interfaccia1> [interfaccia2 ...] <num_thread_analizzatori>\n", argv[0]);
        return 1;
    }

    int num_analyzer_threads = atoi(argv[argc - 1]);
    if (num_analyzer_threads <= 0) {
        fprintf(stderr, "Il numero di thread analizzatori deve essere positivo.\n");
        return 1;
    }

    // inizializzo la queue
    arp_queue_init(&arp_queue);


    // inizializzo il mutex per stdout
    pthread_mutex_init(&stdout_mutex, NULL);
    


    // avvio i receivers
    pthread_t receiver_threads[argc-2];
    printf("Avvio dei thread ricevitori per le interfacce:\n");

    for(int i=1; i < argc-1; i++) {
        receiver_threads[i] = start_receiver_thread(argv[i]);        
    }
    
    
    // avvio gli analyzers
    start_arp_analyzer_pool(num_analyzer_threads);


    printf("\nProgramma avviato. Premere Ctrl+C per terminare.\n\n");
    pthread_exit(NULL);

    return 0;
}