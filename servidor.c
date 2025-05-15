/* O servidor é responsável por transmitir aos clientes uma nova configuração
 * para o PowerUDP via MULTICAST.
 *
 * Os clientes conectam via TCP.
 * */

#include <arpa/inet.h>
#include <bits/pthreadtypes.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "powerudp.h"

#define SERVER_PORT 9000
#define PSK "337b8d2c1e132acd75171f1acf0e73b20bc9541720d5003813f59ef0ad51f86f"

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

void *handle_client(void *arg) {
  struct Threads *args = (struct Threads *)arg;
  int fd = args->client_fd;

  PU_RegisterMessage msg;
  ssize_t len = read(fd, &msg, sizeof(msg));
  if (len != sizeof(msg)) {
    perror("erro a ler mensagem");
    close(fd);
    free(args);
    return NULL;
  }

  if (strncmp(msg.psk, PSK, 64) != 0) {
    printf("psk invalida");
    close(fd);
    free(args);
    return NULL;
  }
  printf("autenticado!");

  PU_ConfigMessage config;
  len = read(fd, &config, sizeof(config));
  if (len != sizeof(config)) {
    perror("Erro ao ler ConfigMessage");
    close(fd);
    free(args);
    return NULL;
  }

  pthread_mutex_lock(&mutex);
  printf("a enviar multicast com config");
  sendto(args->udp_sock, &config, sizeof(config), 0,
         (struct sockaddr *)&args->multicast_addr,
         sizeof(args->multicast_addr));
  pthread_mutex_unlock(&mutex);
  close(fd);
  free(args);
  return NULL;
}

int main(int argc, char *argv[]) {
  if (argc != 3) {
    perror("servidor [hostname] [port]");
    exit(EXIT_FAILURE);
  }

  char *addr = argv[1];
  int port = atoi(argv[2]);
  if (port < 1) {
    perror("servidor [hostname] [port]");
    exit(EXIT_FAILURE);
  }

  // TCP
  int tcp_sock, client_fd;
  struct sockaddr_in server_addr, client_addr;
  socklen_t client_len = sizeof(client_addr);

  tcp_sock = socket(AF_INET, SOCK_STREAM, 0);
  if (tcp_sock < 0) {
    perror("Erro a criar socket TCP");
    exit(EXIT_FAILURE);
  }

  // socket
  bzero(&server_addr, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
  server_addr.sin_port = htons(SERVER_PORT);
  if (bind(tcp_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) <
      0) {
    perror("Erro a dar bind de socket");
    exit(EXIT_FAILURE);
  }
  if (listen(tcp_sock, 5) < 0) {
    perror("Erro a dar listen de socket");
    exit(EXIT_FAILURE);
  }

  // multicast
  int udp_sock;
  struct sockaddr_in multicast_addr;
  char message[] = "Hello, Multicast!";

  /* criar socket */
  udp_sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (udp_sock < 0) {
    perror("Erro ao criar socket");
    exit(EXIT_FAILURE);
  }

  /* configurar socket */
  memset(&multicast_addr, 0, sizeof(multicast_addr));
  multicast_addr.sin_family = AF_INET;
  multicast_addr.sin_addr.s_addr = inet_addr(argv[1]);
  multicast_addr.sin_port = htons(port);

  /* ativar multicast */
  int enable = 1;
  if (setsockopt(udp_sock, IPPROTO_IP, IP_MULTICAST_TTL, &enable,
                 sizeof(enable)) < 0) {
    perror("Erro ao configurar multicast");
    exit(EXIT_FAILURE);
  }

  /* enviar mensagem multicast */
  int sendto_len =
      sendto(udp_sock, message, strlen(message), 0,
             (struct sockaddr *)&multicast_addr, sizeof(multicast_addr));
  if (sendto_len < 0) {
    perror("Erro ao enviar mensagem");
    exit(1);
  }

  while (1) {
    struct Threads *args = malloc(sizeof(struct Threads));
    args->client_fd = accept(tcp_sock, NULL, &client_len);
    if (args->client_fd < 0) {
      perror("erro a aceitar");
      free(args);
      continue;
    }

    args->udp_sock = udp_sock;
    args->multicast_addr = multicast_addr;

    pthread_t tid;
    if (pthread_create(&tid, NULL, handle_client, args) != 0) {
      perror("error a criar thread");
      close(args->client_fd);
      free(args);
    } else {
      pthread_detach(tid);
    }
  }

  close(tcp_sock);
  close(udp_sock);
  return 0;
}
