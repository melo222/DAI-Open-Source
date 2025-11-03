#ifndef LEASE_T_H
#define LEASE_T_H

#include <pthread.h>
#include <arpa/inet.h>   


#define LEASES_FILE "/var/lib/misc/dnsmasq.leases"
#define LINE_MAX_LEN 256
#define MAC_LEN 17
#define IP_LEN INET_ADDRSTRLEN
#define ROUTER_IP_STR   "192.168.10.1"
#define ROUTER_MAC_STR  "08:00:27:68:55:09" 

// associazione IP-MAC
typedef struct {
    char mac[MAC_LEN + 1]; // +1 per \0
    char ip[IP_LEN];       
} lease_entry_t;

// struttura per la cache globale dei lease 
typedef struct {
    lease_entry_t *entries; // array di lease_entry_t
    size_t count;           // num di lease 
    pthread_mutex_t *mutex;  // per accesso alle entries 
    pthread_mutex_t *stdout_mutex;
} lease_cache_t;

// Argomenti per il thread di aggiornamento
typedef struct {
    lease_cache_t *cache;
    int update_interval_sec; // intervallo di aggiornamento in secondi
} lease_updater_t_args;

void lease_cache_init(lease_cache_t *cache);

// dunzione principale che carica/aggiorna i lease dal file.
// questa funzione blocca e sblocca il mutex della cache internamente.
int lease_cache_update(lease_cache_t *cache);

// Funzione di ricerca thread-safe nella cache
int lease_cache_check(lease_cache_t *cache, const char *search_ip_str, const char *search_mac_str);

// Routine del thread di aggiornamento
void *lease_updater_thread(void *arg);

// Funzione per avviare il thread di aggiornamento
pthread_t start_lease_updater_thread(lease_updater_t_args *args);

void print_cache(lease_cache_t *cache);

#endif // LEASE_T_H