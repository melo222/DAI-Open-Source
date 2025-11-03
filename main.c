#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include "arp_queue.h"
#include "lease_t.h"
#include "receiver_t.h"
#include "analyzer_t.h"

// funzione per avviare ogni thread ricevitore ARP
// pthread_t start_receiver_thread(const char *iface_name);

// funzione per avviare il pool di thread analizzatori di ARP
// void start_arp_analyzer_pool(int num_threads);

// mutex per la gestione concorrente di stdout
// pthread_mutex_t stdout_mutex;

int main(int argc, char *argv[]) {

    setvbuf(stdout, NULL, _IONBF, 0); 

    if (argc < 3) {
        fprintf(stderr, "Uso: %s <interfaccia1> [interfaccia2 ...] <num_thread_analizzatori>\n", argv[0]);
        return 1;
    }

    // check num analyzers

    int num_analyzer = atoi(argv[argc - 1]);
    if (num_analyzer <= 0) {
        fprintf(stderr, "Il numero di thread analizzatori deve essere positivo.\n");
        return 1;
    }

    //STDOUT_MUTEX
    // inizializzo il mutex per stdout
    pthread_mutex_t stdout_mutex;    
    pthread_mutex_init(&stdout_mutex, NULL);

    // QUEUE
    // coda condivisa di associazioni ARP 
    arp_association_queue_t arp_queue;
    // inizializzo la queue
    arp_queue_init(&arp_queue,&stdout_mutex);


    // LEASE UPDATER
    // parametri
    lease_cache_t lease_cache; 
    pthread_t updater_tid;
    lease_updater_t_args updater_args;
    int UPDATE_INTERVAL = 5; 
    
    // init e caricamento entry all'avviop
    lease_cache_init(&lease_cache);
    lease_cache.stdout_mutex = &stdout_mutex;
    lease_cache_update(&lease_cache);

    //setting dei parametri
    updater_args.cache = &lease_cache;
    updater_args.update_interval_sec = UPDATE_INTERVAL;

    // avvio del thread
    updater_tid = start_lease_updater_thread(&updater_args);


    // RECEIVERS
    // n receivers threads
    int num_receivers = argc-2;
    pthread_t receiver_threads[num_receivers];
    // threads args
    receiver_t_args *receiver_args;
    receiver_args = calloc(num_receivers,sizeof(receiver_t_args));

    if (receiver_args == NULL) {
        perror("errore nell'allocazione della memoria degli argomenti dei threads receivers\n");
        pthread_mutex_destroy(&stdout_mutex);
        return 1;
    }

    printf("Avvio dei thread ricevitori per le interfacce:\n");

    for(int i=0; i < num_receivers; i++) {
        receiver_args[i].num = i+1;
        receiver_args[i].interface = argv[i+1];
        receiver_args[i].queue = &arp_queue;
        receiver_threads[i] = start_receiver_thread(&receiver_args[i],&stdout_mutex);
    }
    
    
    // ANALYZERS
    pthread_t analyzers_threads[num_analyzer];
    analyzer_t_args *analyzer_args;
    analyzer_args = calloc(num_analyzer,sizeof(analyzer_t_args));
    if (analyzer_args == NULL) {
        perror("errore nell'allocazione della memoria degli argomenti dei threads analyzers\n");
        pthread_mutex_destroy(&stdout_mutex);
        return 1;
    }
    pthread_mutex_lock(&stdout_mutex);
    printf("Avvio dei thread analizzatori:\n");
    pthread_mutex_unlock(&stdout_mutex);

    // avvio gli analyzers
    for(int i=0; i < num_analyzer; i++) {
        analyzer_args[i].num = i+1;
        analyzer_args[i].queue = &arp_queue;
        analyzer_args[i].lease_cache = &lease_cache;
        analyzers_threads[i] = start_analyzer_thread(&analyzer_args[i],&stdout_mutex);
    }


    printf("\nProgramma avviato. Premere Ctrl+C per terminare.\n\n");

    for (int i = 0; i < num_receivers; i++) {
        pthread_join(receiver_threads[i], NULL);
    }

    for (int i = 0; i < num_analyzer; i++) {
        pthread_join(analyzers_threads[i], NULL);
    }

    pthread_join(updater_tid, NULL);
    
    pthread_exit(NULL);

    return 0;
}