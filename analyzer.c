#define _POSIX_C_SOURCE 199309L
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <arpa/inet.h> 
#include <time.h> 
#include "analyzer_t.h"
#include "arp_queue.h"

/* Funzione helper per calcolare la differenza in microsecondi */
double time_diff_micros(struct timespec start, struct timespec end) {
    return (double)(end.tv_sec - start.tv_sec) * 1000000.0 + 
           (double)(end.tv_nsec - start.tv_nsec) / 1000.0;
}

void analyze_arp_association(arp_association_t *association, lease_cache_t *lease_cache, dai_metrics_t *metrics) {
    char mac_str[18], mac_sender[18], ip_addr[INET_ADDRSTRLEN];
      
    mac_to_str(association->mac_addr, mac_str);
    mac_to_str(association->mac_addr_sender, mac_sender);
    inet_ntop(AF_INET, &association->ip_addr, ip_addr, INET_ADDRSTRLEN);

    /* LOGICA DI VALIDAZIONE */
    int is_valid = lease_cache_check(lease_cache, ip_addr, mac_str);

    /* METRICHE: CALCOLO TEMPI */
    struct timespec end_time;
    clock_gettime(CLOCK_MONOTONIC, &end_time);
    double latency_us = time_diff_micros(association->reception_time, end_time);

    /* Aggiornamento statistiche */
    if (metrics) {
        pthread_mutex_lock(&metrics->mutex);
        metrics->total_processed++;
        metrics->total_latency_accum += latency_us;
        if (!is_valid) {
            metrics->attacks_detected++;
        }
        pthread_mutex_unlock(&metrics->mutex);
    }

    /* Output visivo SOLO se è un attacco (per non intasare il log durante i test) */
    // commnto per non avere latenza di stampa nei test
    // if (!is_valid) {
    //     pthread_mutex_lock(lease_cache->stdout_mutex);
    //     printf("============================================\n");        
    //     printf("====== ### ALLERT ### ATTACCO RILEVATO =====\n");
    //     printf("============(Latenza: %.2f us)==============\n", latency_us);
    //     printf("==========MAC=%s=============\n",mac_sender);
    //     pthread_mutex_unlock(lease_cache->stdout_mutex);
    // } 
}

void *analyzer_thread(void *args) {
    analyzer_t_args *t_args = (analyzer_t_args *) args;
    arp_association_queue_t *arp_queue = t_args->queue; 

    pthread_mutex_lock(t_args->stdout_mutex);
    printf("\t - Thread Analyzer numero:%d avviato\n", t_args->num);
    pthread_mutex_unlock(t_args->stdout_mutex);

    while (1) {
        arp_association_t *association = dequeue_arp_association(arp_queue);

        if (association) {
            /* Passo anche le metriche alla funzione di analisi */
            analyze_arp_association(association, t_args->lease_cache, t_args->metrics); 
            free_arp_association(association);     
        }
    }
    pthread_exit(NULL);
}

pthread_t start_analyzer_thread(analyzer_t_args* args, pthread_mutex_t* mutex) {
    args->stdout_mutex = mutex;
    pthread_t analyzer_tid;
    if(pthread_create(&analyzer_tid, NULL, (void *) analyzer_thread, args) != 0) {
        perror("Errore nella creazione del thread analizzatore");
        free(args);
        exit(1);
    }
    return analyzer_tid;
}