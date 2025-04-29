#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include "arp_queue.h"

// Dichiarazione della coda condivisa di associazioni ARP (globale)
arp_association_queue_t arp_association_queue;

// Dichiarazione della funzione per avviare il thread ricevitore ARP
pthread_t start_receiver_thread(const char *interface_name, const char *filter_str);

// Dichiarazione della funzione per avviare il pool di thread analizzatori di ARP
void start_arp_analyzer_pool(int num_threads);

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Uso: %s <interfaccia> <num_thread_analizzatori>\n", argv[0]);
        return 1;
    }

    const char *interface_name = argv[1];
    int num_analyzer_threads = atoi(argv[2]);
    if (num_analyzer_threads <= 0) {
        fprintf(stderr, "Il numero di thread analizzatori deve essere positivo.\n");
        return 1;
    }

    // Inizializza la coda per le associazioni ARP
    arp_queue_init(&arp_association_queue);

    // Avvia il thread ricevitore ARP
    pthread_t receiver_thread = start_receiver_thread(interface_name, "arp and arp[7] == 2");

    // Avvia il pool di thread analizzatori di ARP
    start_arp_analyzer_pool(num_analyzer_threads);

    printf("Programma avviato. Premere Ctrl+C per terminare.\n");
    pthread_exit(NULL);

    return 0;
}       