#ifndef RECEIVER_T_H
#define RECEIVER_T_H
#include <pthread.h>
#include <stdlib.h>
#include "arp_queue.h"

typedef struct {
    int num;
    // pthread_t t_id;
    pthread_mutex_t* stdout_mutex;
    char *interface;
    arp_association_queue_t *queue;
} receiver_t_args;

pthread_t start_receiver_thread(receiver_t_args* args, pthread_mutex_t* mutex);
#endif