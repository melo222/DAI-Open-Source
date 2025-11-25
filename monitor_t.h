#ifndef MONITOR_T_H
#define MONITOR_T_H

#include <pthread.h>
#include <stdio.h>
#include "arp_queue.h" // Qui dentro c'è definita dai_metrics_t

// Struttura per passare gli argomenti al thread monitor
typedef struct {
    dai_metrics_t *metrics;
    arp_association_queue_t *queue;
    pthread_mutex_t *stdout_mutex;
    FILE *csv_file;
} monitor_args_t;

// Funzione per avviare il thread di monitoraggio
pthread_t start_monitor_thread(monitor_args_t *args);

#endif