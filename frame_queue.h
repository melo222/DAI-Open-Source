#ifndef FRAME_QUEUE_H
#define FRAME_QUEUE_H

#include <pthread.h>

// Struttura per rappresentare una trama
typedef struct {
    unsigned char *data;
    int len;
} frame_t;

// Struttura per la coda
typedef struct {
    frame_t *buffer[100]; // Usa la tua definizione di MAX_QUEUE_SIZE se l'hai definita come macro
    int head;
    int tail;
    int count;
    pthread_mutex_t mutex;
    pthread_cond_t not_full;
    pthread_cond_t not_empty;
} frame_queue_t;

// Prototipi delle funzioni per la coda
void queue_init(frame_queue_t *queue);
void enqueue_frame(frame_queue_t *queue, const unsigned char *frame, int len);
frame_t *dequeue_frame(frame_queue_t *queue);
void free_frame(frame_t *frame);

#endif