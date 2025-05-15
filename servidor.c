/* O servidor é responsável por transmitir aos clientes uma nova configuração
 * para o PowerUDP via MULTICAST.
 *
 * Os clientes conectam via TCP.
 * */

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
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

PU_ConfigMessage config;
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

int multicast_sock;
struct sockaddr_in multicast_addr;
int tcp_sock;

typedef struct ThreadArgs {
  struct sockaddr_in client_addr;
  int client_fd;
} ThreadArgs;

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

int main(int argc, char *argv[]) {
  if (argc != 3) {
    fputs("servidor: <tcp_bind_ip> <tcp_port>\n", stderr);
    exit(EXIT_FAILURE);
  }

  struct sockaddr_in tcp_server_addr;
  char *tcp_bind_ip = argv[1];
  int tcp_port = atoi(argv[2]);

  if (tcp_port < 1 || tcp_port > 65535) {
    fprintf(stderr, "Invalid TCP port: %d\n", tcp_port);
    exit(EXIT_FAILURE);
  }

  tcp_sock = socket(AF_INET, SOCK_STREAM, 0);
  if (tcp_sock < 0) {
    perror("TCP socket creation failed");
    exit(EXIT_FAILURE);
  }

  memset(&tcp_server_addr, 0, sizeof(tcp_server_addr));
  tcp_server_addr.sin_family = AF_INET;
  tcp_server_addr.sin_port = htons(tcp_port);
  
  if (inet_pton(AF_INET, tcp_bind_ip, &tcp_server_addr.sin_addr) <= 0) {
    fprintf(stderr, "Invalid TCP bind IP: %s\n", tcp_bind_ip);
    close(tcp_sock);
    exit(EXIT_FAILURE);
  }

  int reuse = 1;
  if (setsockopt(tcp_sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
    perror("setsockopt(SO_REUSEADDR) failed");
    close(tcp_sock);
    exit(EXIT_FAILURE);
  }

  if (bind(tcp_sock, (struct sockaddr *)&tcp_server_addr, sizeof(tcp_server_addr)) < 0) {
    perror("TCP bind failed");
    close(tcp_sock);
    exit(EXIT_FAILURE);
  }

  if (listen(tcp_sock, 5) < 0) {
    perror("TCP listen failed");
    close(tcp_sock);
    exit(EXIT_FAILURE);
  }

  multicast_sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (multicast_sock < 0) {
    perror("Erro ao criar socket");
    exit(EXIT_FAILURE);
  }

  memset(&multicast_addr, 0, sizeof(multicast_addr));
  multicast_addr.sin_family = AF_INET;
  multicast_addr.sin_addr.s_addr = inet_addr(MULTICAST_GROUP);
  multicast_addr.sin_port = htons(MULTICAST_PORT);

  int enable = 1;
  if (setsockopt(multicast_sock, IPPROTO_IP, IP_MULTICAST_TTL, &enable, sizeof(enable)) < 0) {
    perror("Erro ao configurar multicast");
    exit(EXIT_FAILURE);
  }

  // Main loop changes start here
  fd_set read_fds;
  struct timeval tv;

  while (1) {
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
      args->client_fd = accept(tcp_sock, (struct sockaddr *)&args->client_addr, &client_len);

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
