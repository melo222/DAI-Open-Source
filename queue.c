#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

#define MAX_QUEUE_SIZE 100 // Dimensione massima della coda

// Struttura per rappresentare una trama
typedef struct {
    unsigned char *data;
    int len;
} frame_t;

// Struttura per la coda
typedef struct {
    frame_t *buffer[MAX_QUEUE_SIZE];
    int head;
    int tail;
    int count;
    pthread_mutex_t mutex;
    pthread_cond_t not_full;
    pthread_cond_t not_empty;
} frame_queue_t;

// Inizializza la coda
void queue_init(frame_queue_t *queue) {
    queue->head = 0;
    queue->tail = 0;
    queue->count = 0;
    pthread_mutex_init(&queue->mutex, NULL);
    pthread_cond_init(&queue->not_full, NULL);
    pthread_cond_init(&queue->not_empty, NULL);
}

// Inserisci una trama nella coda
void enqueue_frame(frame_queue_t *queue, const unsigned char *frame, int len) {
    pthread_mutex_lock(&queue->mutex);
    while (queue->count == MAX_QUEUE_SIZE) {
        // La coda è piena, attendi che ci sia spazio
        pthread_cond_wait(&queue->not_full, &queue->mutex);
    }

    queue->buffer[queue->tail] = malloc(sizeof(frame_t));
    if (queue->buffer[queue->tail] == NULL) {
        perror("Errore nell'allocazione di memoria per la trama");
        pthread_mutex_unlock(&queue->mutex);
        return;
    }
    queue->buffer[queue->tail]->data = malloc(len);
    if (queue->buffer[queue->tail]->data == NULL) {
        perror("Errore nell'allocazione di memoria per i dati della trama");
        free(queue->buffer[queue->tail]);
        pthread_mutex_unlock(&queue->mutex);
        return;
    }
    memcpy(queue->buffer[queue->tail]->data, frame, len);
    queue->buffer[queue->tail]->len = len;

    queue->tail = (queue->tail + 1) % MAX_QUEUE_SIZE;
    queue->count++;

    // Segnala che la coda non è più vuota
    pthread_cond_signal(&queue->not_empty);
    pthread_mutex_unlock(&queue->mutex);
}

// Estrai una trama dalla coda
frame_t *dequeue_frame(frame_queue_t *queue) {
    pthread_mutex_lock(&queue->mutex);
    while (queue->count == 0) {
        // La coda è vuota, attendi che ci siano elementi
        pthread_cond_wait(&queue->not_empty, &queue->mutex);
    }

    frame_t *frame = queue->buffer[queue->head];
    queue->head = (queue->head + 1) % MAX_QUEUE_SIZE;
    queue->count--;

    // Segnala che la coda non è più piena
    pthread_cond_signal(&queue->not_full);
    pthread_mutex_unlock(&queue->mutex);
    return frame;
}

// Funzione per liberare la memoria di una trama estratta
void free_frame(frame_t *frame) {
    if (frame) {
        free(frame->data);
        free(frame);
    }
}