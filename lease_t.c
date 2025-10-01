#include "lease_t.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h> // Per sleep

// init
void lease_cache_init(lease_cache_t *cache) {
    cache->mutex = malloc(sizeof(pthread_mutex_t));     
    if (cache->mutex == NULL) {
        perror("Errore nell'allocazione della memoria per il mutex della cache lease");
        exit(1);
    }
    // cache->stdout_mutex = malloc(sizeof(pthread_mutex_t));     
    // if (cache->stdout_mutex == NULL) {
    //     perror("Errore nell'allocazione della memoria per il stdout_mutex della cache lease");
    //     exit(1);
    // }

    cache->entries = NULL;
    cache->count = 0;
    if(pthread_mutex_init(cache->mutex, NULL) != 0){
        perror("errore nell'init mutex cache\n");
    }
}

// parser lines
static int parse_lease_line(const char *line, lease_entry_t *entry) {
    long timestamp;
    char hostname[64];
    
    // Formato: <timestamp> <mac> <ip> <hostname> ...
    int items_read = sscanf(line, "%ld %17s %15s %63s", 
                            &timestamp, entry->mac, entry->ip, hostname);

    // Controlla che almeno i campi MAC e IP siano stati letti (items_read >= 3)
    return (items_read >= 3);
}

// updater: legge il file e costituisce la cache.
int lease_cache_update(lease_cache_t *cache) {
    FILE *file = fopen(LEASES_FILE, "r");
    if (file == NULL) {
        perror("errore nell'apertura del file /var/lib/misc/dnsmasq.leases");
        return -1; 
    }

    lease_entry_t *new_entries = NULL;
    size_t current_capacity = 32;
    size_t new_count = 0;

    // Alloca capacità iniziale
    new_entries = malloc(current_capacity * sizeof(lease_entry_t));
    if (new_entries == NULL) {
        fclose(file);
        return -1;
    }

    char line[LINE_MAX_LEN];
    while (fgets(line, sizeof(line), file)) {
        if (new_count >= current_capacity) {
            current_capacity *= 2;

            lease_entry_t *temp = realloc(new_entries, current_capacity * sizeof(lease_entry_t));
            
            if (temp == NULL) {
                perror("Errore di realloc cache update\n");
                free(new_entries);
                fclose(file);
                return -1;
            }

            new_entries = temp;
        }

        if (parse_lease_line(line, &new_entries[new_count])) {
            new_count++;
        }
    }
    
    fclose(file);

    // lock della cache per swap
    pthread_mutex_lock(cache->mutex);
    
    // free delle vecchie entry
    if (cache->entries != NULL) {
        free(cache->entries);
    }
     
    // sssegna la nuova cache
    cache->entries = new_entries;
    cache->count = new_count;
    
    pthread_mutex_unlock(cache->mutex);

    return new_count;
}

// stampa cace
void print_cache(lease_cache_t *cache) {
    for (size_t i = 0; i < cache->count; i++){
        printf("\t%lu) MAC=%s IP=%s\n",i,cache->entries[i].mac,cache->entries[i].ip);
    }
}

// funzione di ricerca nella cache 
int lease_cache_check(lease_cache_t *cache, const char *search_ip_str, const char *search_mac_str) {
    int found = 0;

    // pthread_mutex_lock(cache->stdout_mutex);
    // printf("start strcpm tra cache->entries e ip_str/mac_str\n");
    // pthread_mutex_unlock(cache->stdout_mutex);

    pthread_mutex_lock(cache->mutex);
    
    for (size_t i = 0; i < cache->count; i++) {
        if (strcmp(cache->entries[i].ip, search_ip_str) == 0 && strcmp(cache->entries[i].mac, search_mac_str) == 0) {
            found = 1;
            break;
        }
    }
    
    pthread_mutex_unlock(cache->mutex);
    return found;
}

// routine del thread updater 
void *lease_updater_thread(void *arg) {
    lease_updater_t_args *t_args = (lease_updater_t_args *) arg;
    lease_cache_t *cache = t_args->cache;
    int interval = t_args->update_interval_sec;
    
    pthread_mutex_lock(t_args->cache->stdout_mutex);
    printf("Thread Updater Lease avviato (Intervallo: %d sec)\n\n", interval);
    pthread_mutex_unlock(t_args->cache->stdout_mutex);

    while (1) {
        lease_cache_update(cache);

        pthread_mutex_lock(t_args->cache->stdout_mutex);
        printf("---LEASES CACHE---\n");
        print_cache(cache);
        pthread_mutex_unlock(t_args->cache->stdout_mutex);

        pthread_mutex_lock(t_args->cache->stdout_mutex);
        printf("\n---Cache lease DHCP updated---\n\n");
        pthread_mutex_unlock(t_args->cache->stdout_mutex);
        
        sleep(interval);
    }
    
    // Il thread non dovrebbe mai uscire da questo loop
    return NULL; 
}

// Avvio del thread di aggiornamento cache
pthread_t start_lease_updater_thread(lease_updater_t_args *args) {
    pthread_t updater_tid;
    if (pthread_create(&updater_tid, NULL, lease_updater_thread, args) != 0) {
        perror("Errore nella creazione del thread updater lease");
        exit(1);
    }
    return updater_tid;
}