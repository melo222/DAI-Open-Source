#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <arpa/inet.h> // Per inet_ntoa
#include "analyzer_t.h"
#include "arp_queue.h"

// Funzione di esempio per analizzare un'associazione ARP
// si può eliminare il parametro stdout-mutex perchè già presente nella cache
void analyze_arp_association(arp_association_t *association, lease_cache_t *lease_cache) {
    char mac_str[18], mac_sender[18], ip_addr[INET_ADDRSTRLEN];
      
    mac_to_str(association->mac_addr,mac_str);
    mac_to_str(association->mac_addr_sender,mac_sender);
    inet_ntop(AF_INET,&association->ip_addr,ip_addr,INET_ADDRSTRLEN);

    pthread_mutex_lock(lease_cache->stdout_mutex);
    printf("Thread analizzatore %lu ha estratto dalla queue: MAC=%s, IP=%s, MAC_SENDER=%s\n",
           pthread_self(), mac_str, ip_addr, mac_sender);
    pthread_mutex_unlock(lease_cache->stdout_mutex);

    // pthread_mutex_lock(lease_cache->stdout_mutex);
    // printf("pre lease_cache_check\n");
    // pthread_mutex_unlock(lease_cache->stdout_mutex);
    
    int is_valid = lease_cache_check(lease_cache, ip_addr, mac_str);

    pthread_mutex_lock(lease_cache->stdout_mutex);
    if (is_valid){
        printf("============================================\n");        
        printf("FINTA ANALISI TERMINATA, ECCEZIONE SOLLEVATA\n");
        printf("============================================\n");
        printf("==========MAC=%s=============\n",mac_sender);
    }
    else{
        printf("Analisi terminata, eccezione NON sollevata\n\n");
    }
    pthread_mutex_unlock(lease_cache->stdout_mutex);

    /*
    
    srand(time(NULL));

    pthread_mutex_lock(stdout_mutex);
    if ((rand()%10) == 3){
        printf("============================================\n");        
        printf("FINTA ANALISI TERMINATA, ECCEZIONE SOLLEVATA\n");
        printf("============================================\n");
        printf("==========MAC=%s=============\n",mac_sender);
    }
    else{
        printf("Analisi terminata, eccezione NON sollevata\n");
    }
    pthread_mutex_unlock(stdout_mutex);

    */

}


// la routine eseguita per ogni thread
void *analyzer_thread(void *args) {
    analyzer_t_args *t_args = (analyzer_t_args *) args;
    arp_association_queue_t *arp_queue = t_args->queue; // Dichiarazione della coda globale

    pthread_mutex_lock(t_args->stdout_mutex);
    printf("\t - Thread Analyzer numero:%d avviato\n", t_args->num);
    pthread_mutex_unlock(t_args->stdout_mutex);

    while (1) {
        // prendo dalla funzione implementata in queue.c una associazione e la passo al thread
        arp_association_t *association = dequeue_arp_association(arp_queue);

        // pthread_mutex_lock(t_args->stdout_mutex);
        // printf("associazione dequeued\n");
        // pthread_mutex_unlock(t_args->stdout_mutex);

        if (association) {
            analyze_arp_association(association,t_args->lease_cache); 

            // pthread_mutex_lock(t_args->stdout_mutex);
            // printf("associazione analizzata\n");
            // pthread_mutex_unlock(t_args->stdout_mutex);

            free_arp_association(association);     // Implementata in queue

            // pthread_mutex_lock(t_args->stdout_mutex);
            // printf("associazione freed\n");
            // pthread_mutex_unlock(t_args->stdout_mutex);
        }
        // Se la coda è vuota, il thread rimarrà bloccato nella dequeue fino a quando non arriva una nuova associazione
    }
    pthread_exit(NULL);
}

// Funzione per creare e avviare il pool di thread analizzatori di ARP
pthread_t start_analyzer_thread(analyzer_t_args* args, pthread_mutex_t* mutex) {
    args->stdout_mutex = mutex;
    pthread_t analyzer_tid;
    if(pthread_create(&analyzer_tid, NULL, (void *) analyzer_thread, args) != 0) {
        printf("Errore nella creazione del thread ricevitore");
        free(args);
        exit(1);
    }
    return analyzer_tid;
}