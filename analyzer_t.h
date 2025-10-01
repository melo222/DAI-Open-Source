#ifndef ANALYZER_T_H
#define ANALYZER_T_H
#include <pthread.h>
#include <stdlib.h>
#include "arp_queue.h"
#include "lease_t.h"

typedef struct {
    // pthread_t t_id;
    int num;
    pthread_mutex_t* stdout_mutex;
    lease_cache_t *lease_cache;
    arp_association_queue_t *queue;
} analyzer_t_args;

pthread_t start_analyzer_thread(analyzer_t_args* args, pthread_mutex_t* mutex);
#endif 