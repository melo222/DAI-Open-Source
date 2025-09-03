#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <arpa/inet.h> // Per inet_ntoa
#include "arp_queue.h"

// Dichiarazione esterna del mutex
extern pthread_mutex_t stdout_mutex;



#include <time.h> // per fermare random una analisi fino a quando non la sviluppo


// Dichiarazione della coda condivisa di associazioni ARP (assicurati che sia globale o passata ai thread)
arp_association_queue_t arp_association_queue;

// Funzione di esempio per analizzare un'associazione ARP
void analyze_arp_association(arp_association_t *association) {
    char mac_str[18], mac_sender[18];
    sprintf(mac_str, "%02x:%02x:%02x:%02x:%02x:%02x",
            association->mac_addr[0], association->mac_addr[1], association->mac_addr[2],
            association->mac_addr[3], association->mac_addr[4], association->mac_addr[5]);
    sprintf(mac_sender, "%02x:%02x:%02x:%02x:%02x:%02x",
            association->mac_addr_sender[0], association->mac_addr_sender[1], association->mac_addr_sender[2],
            association->mac_addr_sender[3], association->mac_addr_sender[4], association->mac_addr_sender[5]);
    char ip_addr[4];
    inet_ntop(AF_INET,&association->ip_addr,ip_addr,INET_ADDRSTRLEN);
    printf("Thread analizzatore %lu ha estratto dalla queue: MAC=%s, IP=%s\n",
           pthread_self(), mac_str, ip_addr);
    
    /*
    
    SCRIVERE QUI L'ANALISI TRAMITE DHCP CHECK
    
    */
    srand(time(NULL));

    if ((rand()%21) == 3){
        printf("============================================\n");        
        printf("FINTA ANALISI TERMINATA, ECCEZIONE SOLLEVATA\n");
        printf("============================================\n");
        printf("========%s========",mac_sender);
    }
}

// la routine eseguita per ogni thread
void *analyzer_thread(void *arg) {
    while (1) {
        // prendo dalla funzione implementata in queue.c una associazione e la passo al thread
        arp_association_t *association = dequeue_arp_association(&arp_association_queue); 
        if (association) {
            analyze_arp_association(association); 
            free_arp_association(association); // Implementata in queue
        }
        // Se la coda è vuota, il thread rimarrà bloccato nella dequeue fino a quando non arriva una nuova associazione
    }
    pthread_exit(NULL);
}

// Funzione per creare e avviare il pool di thread analizzatori di ARP
void start_arp_analyzer_pool(int num_threads) {
    pthread_t analyzer_tids[num_threads];
    // ciclo che esegue pthread_create, funzione per creare thread ed eseguire una routine annessa
    for (int i = 0; i < num_threads; i++) {
        if (pthread_create(&analyzer_tids[i], NULL, analyzer_thread, NULL) != 0) {
            perror("Errore nella creazione del thread analizzatore ARP");
            exit(EXIT_FAILURE);
        }
        printf("%d) Thread analizzatore ARP %lu creato.\n", i, analyzer_tids[i]);
    }
}