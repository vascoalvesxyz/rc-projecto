/*
Vasco Alves    2022228207
Rodrigo Faria  2023234032
 _ __   _____      _____ _ __ _   _  __| |_ __
| '_ \ / _ \ \ /\ / / _ \ '__| | | |/ _` | '_ \
| |_) | (_) \ V  V /  __/ |  | |_| | (_| | |_) |
| .__/ \___/ \_/\_/ \___|_|   \__,_|\__,_| .__/
|_|                                      |_|

O PowerUDP permitirá suportar as seguintes funcionalidades:
1. Registo da aplicação cliente no servidor, com recurso a chave pré-configurada;
2. Envio para o servidor de pedidos de alteração à configuração do protocolo ativa na rede;
3. Envio e receção de mensagens UDP para outros hosts, com garantias de confiabilidade de acordo com a configuração ativa; 
*/
#include <arpa/inet.h>
#include <assert.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "powerudp.h"

#define PSK "337b8d2c1e132acd75171f1acf0e73b20bc9541720d5003813f59ef0ad51f86f"
#define MULTICAST_GROUP "239.255.0.1"
#define MULTICAST_PORT 54321

typedef struct ThreadArgs {
  struct sockaddr_in client_addr;
  int client_fd;
} ThreadArgs;

static PU_ConfigMessage config = {10, 1, 1, 1, 10};
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static int multicast_sock;
static int tcp_sock;
static volatile sig_atomic_t running = 1;

static void handle_signal(); 
static bool setup_tcp(int port, int backlog);
static bool setup_multicast();
void *handle_client(void *arg);

static void handle_signal() { running = 0; }

static bool setup_tcp(int port, int backlog) {
  /* verifica que o port é valido */
  if (port < 0 || port > 65535)
    return false;

  /* criar socket tcp */
  tcp_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (tcp_sock < 0) {
    perror("socket() failed");
    return false;
  }

  /* dar bind ao host e port */
  struct sockaddr_in server_addr = {
    .sin_family = AF_INET,
    .sin_port = htons(port),
    .sin_addr.s_addr = htonl(INADDR_ANY)
  };

  if (bind(tcp_sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
    perror("bind() failed");
    close(tcp_sock);
    return false;
  }

  /* ouvir */
  if (listen(tcp_sock, backlog) < 0) {
    perror("listen() failed");
    close(tcp_sock);
    return false;
  }

  printf("tcp setup on port %d\n", port);
  return true;
}

static bool setup_multicast() {
  /* criar socket */
  multicast_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (multicast_sock < 0) {
    perror("setup_multicast: ");
    return false;
  }

  int reuse = 1;
  if (setsockopt(multicast_sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
    perror("setup_multicast: ");
    close(multicast_sock);
    return false;
  }

  /* mudar time-to-live */
  int ttl = 128;
  if (setsockopt(multicast_sock, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl))) {
    perror("setup_multicast: ");
    close(multicast_sock);
    return false;
  }

  /* Configurar endereço */
  struct sockaddr_in multicast_addr;
  memset(&multicast_addr, 0, sizeof(multicast_addr));
  multicast_addr.sin_family = AF_INET;
  multicast_addr.sin_port = htons(MULTICAST_PORT);

  if (bind(multicast_sock, (struct sockaddr*)&multicast_addr, sizeof(multicast_addr)) < 0) {
    perror("setup_multicast: bind() failed");
    close(multicast_sock);
    return false;
  }

  printf("multicast setup on %s:%d\n", MULTICAST_GROUP, MULTICAST_PORT);
  return true;
}

void *handle_client(void *arg) {
  /* Dar dereference e free imediatamente */
  ThreadArgs args = *(ThreadArgs *)arg;
  free(arg);

  static char ip_str[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &args.client_addr.sin_addr, ip_str, sizeof(ip_str));
  int port = ntohs(args.client_addr.sin_port);

  printf("%10s:%-5d quer conectar...\n", ip_str, port);

  char recv[sizeof(PU_RegisterMessage) + 33];
  recv[sizeof(PU_RegisterMessage) + 32] = '\0';

  ssize_t len = read(args.client_fd, &recv, sizeof(PU_RegisterMessage) + 33);
  if (len < sizeof(PU_RegisterMessage)) {
    printf("%10s:%-5d enviou mensagem imcompleta!\n", ip_str, port);
    goto thread_exit;
  }

  if (strncmp(recv, PSK, 64) != 0) {
    printf("%10s:%-5d tinha chave incorrecta!\n", ip_str, port);
    write(args.client_fd, "NAK\0", 4);
    goto thread_exit;
  }

  /* Analizar comando depois de autenticar */
  char *comando_buf = recv + 64;  
  printf("comando_buf: %s\n", comando_buf);

  /* Login */
  if (0 == strncmp("login", comando_buf, 5)) {
    printf("%10s:%-5d login...\n", ip_str, port);
    pthread_mutex_lock(&mutex);
    write(args.client_fd, &config, sizeof(PU_ConfigMessage));
    pthread_mutex_unlock(&mutex);
    printf("%10s:%-5d foi aceite!\n", ip_str, port);
  } 
  /* Config novo */
  else if (0 == strncmp("newcfg", comando_buf, 6)) {
    printf("%10s:%-5d newcfg...\n", ip_str, port);
    write(args.client_fd, "ACK\0", 4);
    PU_ConfigMessage new_config;
    read(args.client_fd, &new_config, sizeof(new_config));
    printf("%10s:%-5d enviou uma configuração nova!\n", ip_str, port);
    memcpy(&config, &new_config, sizeof(new_config));

    pthread_mutex_lock(&mutex);
    write(multicast_sock, (void*) &config, sizeof(PU_ConfigMessage) );
    pthread_mutex_unlock(&mutex);

  }

  write(args.client_fd, "NAK\0", 4);

  thread_exit:
  close(args.client_fd);
  return NULL;
}

int main(int argc, char *argv[]) {
  if (argc != 2) {
    fputs("servidor: <tcp_port>\n", stderr);
    exit(EXIT_FAILURE);
  }

  int tcp_port = atoi(argv[1]);
  if (tcp_port < 0 || tcp_port > 65535) {
    fputs("servidor: <tcp_port>\n", stderr);
    exit(EXIT_FAILURE);
  }

  if (!setup_tcp(tcp_port, 128) ||
      !setup_multicast()) {
    exit(EXIT_FAILURE);
  }

  struct sigaction sa = {.sa_handler = handle_signal, .sa_flags = SA_RESTART};

  sigemptyset(&sa.sa_mask);
  sigaction(SIGINT, &sa, NULL);
  sigaction(SIGTERM, &sa, NULL);

  fd_set read_fds;
  struct timeval tv;

  while (running) {
    FD_ZERO(&read_fds);
    FD_SET(tcp_sock, &read_fds);

    tv.tv_sec = 1;
    tv.tv_usec = 0;

    if (select(tcp_sock + 1, &read_fds, NULL, NULL, &tv) < 0) {
      if (!running) break;
      perror("select error");
      continue;
    }

    if (FD_ISSET(tcp_sock, &read_fds)) {
      ThreadArgs *args = malloc(sizeof(ThreadArgs));
      if (!args) {
        perror("malloc failed");
        continue;
      }

      socklen_t client_len = sizeof(args->client_addr);
      args->client_fd = accept(tcp_sock, (struct sockaddr *)&args->client_addr, &client_len);
      if (args->client_fd < 0) {
        continue;
      }

      pthread_t tid;
      if (pthread_create(&tid, NULL, handle_client, args) != 0) {
        perror("thread creation failed");
        close(args->client_fd);
      } else {
        pthread_detach(tid);
      }
    }
  }

  puts("Exited cleanly.");

  close(tcp_sock);
  close(multicast_sock);
  return 0;
}

