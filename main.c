#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>

// Dichiarazione e inizializzazione della coda condivisa (globale)
frame_queue_t frame_queue;

// Dichiarazioni delle funzioni per avviare i thread
pthread_t start_receiver_thread(const char *interface_name);
void start_analyzer_pool(int num_threads);

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Uso: %s <interfaccia1> [interfaccia2 ...] <num_thread_analizzatori>\n", argv[0]);
        return 1;
    }

    int num_analyzer_threads = atoi(argv[argc - 1]);
    if (num_analyzer_threads <= 0) {
        fprintf(stderr, "Il numero di thread analizzatori deve essere positivo.\n");
        return 1;
    }

    queue_init(&frame_queue);

    // Avvia i thread ricevitori per ogni interfaccia specificata
    pthread_t receiver_threads[argc - 2];
    for (int i = 1; i < argc - 1; i++) {
        receiver_threads[i - 1] = start_receiver_thread(argv[i]);
    }

    // Avvia il pool di thread analizzatori
    start_analyzer_pool(num_analyzer_threads);

    // Il thread main potrebbe fare altro lavoro o semplicemente attendere la terminazione (con meccanismi di join o altro)
    printf("Programma avviato. Premere Ctrl+C per terminare.\n");
    pthread_exit(NULL); // Il thread main termina, ma gli altri thread continueranno a eseguire (a meno che non vengano gestiti diversamente)

    return 0;
}