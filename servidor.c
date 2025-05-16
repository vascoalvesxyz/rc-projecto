/* O servidor é responsável por transmitir aos clientes uma nova configuração
 * para o PowerUDP via MULTICAST.
 *
 * Os clientes conectam via TCP.
 * */

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

static PU_ConfigMessage config;
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static int multicast_sock;
static int tcp_sock;
static volatile sig_atomic_t running = 1;

static void handle_signal() { running = 0; }
static bool setup_multicast(const char *group, int port);
static bool setup_tcp(const char *bind_addr, int port, int backlog);
void *handle_client(void *arg);

int main(int argc, char *argv[]) {
  if (argc != 3) {
    fputs("servidor: <tcp_bind_ip> <tcp_port>\n", stderr);
    exit(EXIT_FAILURE);
  }

  char *tcp_bind_ip = argv[1];
  int tcp_port = atoi(argv[2]);

  if (!setup_tcp(tcp_bind_ip, tcp_port, 10) ||
      !setup_multicast(MULTICAST_GROUP, MULTICAST_PORT)) {
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
      args->client_fd =
          accept(tcp_sock, (struct sockaddr *)&args->client_addr, &client_len);
      puts("accepted client");

      if (args->client_fd < 0) {
        free(args);
        continue;
      }

      pthread_t tid;
      if (pthread_create(&tid, NULL, handle_client, args) != 0) {
        perror("thread creation failed");
        close(args->client_fd);
        free(args);
      } else {
        pthread_detach(tid);
      }
    }
  }

  close(tcp_sock);
  close(multicast_sock);
  return 0;
}

static bool setup_tcp(const char *bind_addr, int port, int backlog) {
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
  struct sockaddr_in server_addr = {.sin_family = AF_INET,
                                    .sin_port = htons(port)};

  if (inet_pton(AF_INET, bind_addr, &server_addr.sin_addr) != 1) {
    fprintf(stderr, "Invalid bind address: %s\n", bind_addr);
    close(tcp_sock);
    return false;
  }

  if (bind(tcp_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) <
      0) {
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

  printf("tcp setup on %s:%d\n", bind_addr, port);
  return true;
}

static bool setup_multicast(const char *group, int port) {
  /* criar socket */
  multicast_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (multicast_sock < 0) {
    perror("setup_multicast: socket() failed");
    return false;
  }

  /* mudar time-to-live */
  int ttl = 32;
  if (setsockopt(multicast_sock, IPPROTO_IP, IP_MULTICAST_TTL, &ttl,
                 sizeof(ttl))) {
    perror("setup_multicast: setsockopt(TTL) failed");
    close(multicast_sock);
    return false;
  }

  /* Configurar endereço */
  struct sockaddr_in multicast_addr;
  memset(&multicast_addr, 0, sizeof(multicast_addr));
  multicast_addr.sin_family = AF_INET;
  multicast_addr.sin_port = htons(port);

  /* validar endereço */
  if (inet_pton(AF_INET, group, &multicast_addr.sin_addr) != 1) {
    fprintf(stderr, "setup_multicast: invalid multicast address: %s\n", group);
    close(multicast_sock);
    return false;
  }

  printf("multicast setup on %s:%d\n", group, port);
  return true;
}

void *handle_client(void *arg) {
  ThreadArgs *args = (ThreadArgs *)arg;

  PU_RegisterMessage msg;
  ssize_t len = read(args->client_fd, &msg, sizeof(msg));
  if (len != sizeof(msg)) {
    perror("erro a ler mensagem");
    goto thread_exit;
  }

  if (strncmp(msg.psk, PSK, 64) != 0) {
    write(args->client_fd, "NACK\0", 5);
    goto thread_exit;
  }

  pthread_mutex_lock(&mutex);
  write(args->client_fd, &config, sizeof(PU_ConfigMessage));
  pthread_mutex_unlock(&mutex);

  printf("Autenticado!\n");

thread_exit:
  close(args->client_fd);
  free(args);
  return NULL;
}
