#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <arpa/inet.h> // Per inet_ntoa
#include "arp_queue.h"

// Dichiarazione della coda condivisa di associazioni ARP (assicurati che sia globale o passata ai thread)
extern arp_association_queue_t arp_association_queue;

// Funzione di esempio per analizzare un'associazione ARP
void analyze_arp_association(arp_association_t *association) {
    char mac_str[18];
    sprintf(mac_str, "%02x:%02x:%02x:%02x:%02x:%02x",
            association->mac_addr[0], association->mac_addr[1], association->mac_addr[2],
            association->mac_addr[3], association->mac_addr[4], association->mac_addr[5]);
    printf("Thread analizzatore %lu ha analizzato: MAC=%s, IP=%s\n",
           pthread_self(), mac_str, inet_ntoa(association->ip_addr));
    // Qui puoi aggiungere la tua logica di analisi specifica
}

void *analyzer_thread(void *arg) {
    while (1) {
        arp_association_t *association = dequeue_arp_association(&arp_association_queue);
        if (association) {
            analyze_arp_association(association);
            free_arp_association(association); // Importante liberare la memoria
        }
        // Se la coda è vuota, il thread rimarrà bloccato nella dequeue fino a quando non arriva una nuova associazione
    }
    pthread_exit(NULL);
}

// Funzione per creare e avviare il pool di thread analizzatori di ARP
void start_arp_analyzer_pool(int num_threads) {
    pthread_t analyzer_tids[num_threads];
    for (int i = 0; i < num_threads; i++) {
        if (pthread_create(&analyzer_tids[i], NULL, analyzer_thread, NULL) != 0) {
            perror("Errore nella creazione del thread analizzatore ARP");
            exit(EXIT_FAILURE);
        }
        printf("Thread analizzatore ARP %lu creato.\n", analyzer_tids[i]);
    }
}