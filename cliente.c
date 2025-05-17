/* O cliente comunica com outros clientes via PowerUDP.
 * O cliente comunica via TCP para pedir uma nova configuração ao Servidor.
 * */
#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <assert.h>
#include <endian.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include "powerudp.h"

#define SV_IP "193.137.101.1"
#define SV_PORT 443

#define MULTICAST_GROUP "239.255.0.1"
#define MULTICAST_PORT 54321

#define PSK     "337b8d2c1e132acd75171f1acf0e73b20bc9541720d5003813f59ef0ad51f86f"

typedef struct {
  int sv_sock;
  int mc_sock;
} global_t;

static global_t global;
static PU_ConfigMessage config = {0};
static uint64_t current_seq = 0;
static volatile sig_atomic_t running = 1;

/* Helpers */
static void* thread_multicast_listener(void* arg);
static void setup_multicast();
static void handle_sigint();

/* PowerUDP */
int pu_init_protocol(const char *server_ip, int server_port, const char *psk);
void pu_close_protocol();

int pu_request_protocol_config(PU_ConfigMessage new_config);
int pu_send_message(const char *destination, const char *message, int len);
int pu_receive_message(char *buffer, int bufsize);
int pu_get_last_message_stats(int *retransmissions, int *delivery_time);
void pu_inject_packet_loss(int probability);

static void* thread_multicast_listener(void* arg) {
  (void)arg;

  setup_multicast();
  assert(global.mc_sock > 0);

  PU_ConfigMessage new_config;
  struct sockaddr_in src_addr;
  socklen_t addr_len = sizeof(src_addr);

  while (running) {  
    ssize_t len = recvfrom(global.mc_sock,  &new_config, sizeof(new_config), 0, (struct sockaddr*)&src_addr, &addr_len);
    if (!running) break;
    
    if (len < 0) {
      perror("[Multicast Listener] recvfrom() failed");
      continue;
    }

    if (len != sizeof(new_config)) {
      fprintf(stderr, "[Multicast Listener] Received incomplete config (%zd/%zu bytes)\n", len, sizeof(new_config));
      continue;
    }

    /* Process multicast message */
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &src_addr.sin_addr, ip_str, sizeof(ip_str));
    printf("[Multicast Listener] Received multicast from %s:%d\n", ip_str, ntohs(src_addr.sin_port));
    printf("[Multicast Listener] New config: Timeout=%d\tBackoff=%d\tRetransmission=%d\tSequence=%d\tMax_Retries=%d\n",
      new_config.base_timeout, new_config.enable_backoff, new_config.enable_retransmission, new_config.enable_sequence, new_config.max_retries);

    memcpy(&config, &new_config, sizeof(config));
  }

  if (global.mc_sock > 0)
    close(global.mc_sock);
  pthread_exit(NULL);
}

static void setup_multicast() {
  /* multicast sock */
  global.mc_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (global.mc_sock < 0) {
    perror("[Multicast Listener] Multicast socket creation failed");
    pthread_exit(NULL);
  }

  /* reuse */
  int reuse = 1;
  if (setsockopt(global.mc_sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
    perror("[Multicast Listener] setsockopt(SO_REUSEADDR) failed");
    close(global.mc_sock);
    pthread_exit(NULL);
  }

  /* usar grupo predefinido */
  struct sockaddr_in addr = {
    .sin_family = AF_INET,
    .sin_port = htons(MULTICAST_PORT),
    .sin_addr.s_addr = INADDR_ANY
  };

  /* bind */
  if (bind(global.mc_sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
    perror("[Multicast Listener] Multicast bind failed");
    close(global.mc_sock);
    pthread_exit(NULL);
  }

  /* mreq */
  struct ip_mreq mreq;
  mreq.imr_multiaddr.s_addr = inet_addr(MULTICAST_GROUP);
  mreq.imr_interface.s_addr = INADDR_ANY; 
  if (setsockopt(global.mc_sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(struct ip_mreq)) < 0) {
    perror("[Multicast Listener] Join multicast group failed");
    close(global.mc_sock);
    pthread_exit(NULL);
  }

  puts("[Multicast Listener] Joined multicast group!");
}

/* Init protocol */
int pu_init_protocol(const char *server_ip, int server_port, const char *psk) {

  /* TCP socket para comunicr com o server */
  global.sv_sock = socket(AF_INET, SOCK_STREAM, 0);
  if (global.sv_sock < 0) {
    fputs("TCP socket creation failed", stderr);
    return -1;
  }

  /* address do servidor */
  struct sockaddr_in sv_addr = {
    .sin_family = AF_INET,
    .sin_port = htons(server_port)
  };

  if (inet_pton(AF_INET, server_ip, &sv_addr.sin_addr) <= 0) {
    fputs("Invalid server address", stderr);
    close(global.sv_sock);
    return -1;
  }

  /* ligar ao servidor */
  if (connect(global.sv_sock, (struct sockaddr *)&sv_addr,
              sizeof(sv_addr)) < 0) {
    fputs("TCP connection failed", stderr);
    close(global.sv_sock);
    return -1;
  }

  /* enviar key via psk */
  if (write(global.sv_sock, psk, strlen(psk)) < 0) {
    fputs("PSK send failed", stderr);
    close(global.sv_sock);
    return -1;
  }

  /* obter resposta do servidor */
  char resposta_serializada[sizeof(PU_ConfigMessage)];
  memset(&resposta_serializada, 0, sizeof(PU_ConfigMessage));
  int recvlen =
      read(global.sv_sock, &resposta_serializada, sizeof(PU_ConfigMessage));
  if (recvlen < 0) {
    fputs("Failed to recieve config message from server.", stderr);
    close(global.sv_sock);
    return -1;
  }

  /* Verificar resposta */
  if (strcmp(resposta_serializada, "NACK\0") == 0) {
    fputs("PSK was incorrect!", stderr);
    close(global.sv_sock);
    return -1;
  } else if (recvlen < (int)sizeof(PU_ConfigMessage)) {
    fputs("Recieved malformed config.", stderr);
    close(global.sv_sock);
    return -1;
  }

  memcpy(&config, resposta_serializada, sizeof(PU_ConfigMessage));
  puts("Successfuly retrieved config!");
  return 0;
}

int pu_send_message(const char *destination, const char *message, int len) {

  const char *host = destination;
  char *seperator = strchr(host, ':');
  if (seperator == NULL) {
    fputs("[ERROR] pu_send_message: does not contain ':' seperator.", stderr);
    return -1;
  }

  *seperator = '\0';

  int port = atoi(seperator + 1);
  if (port <= 0) {
    fputs("[ERROR] pu_send_message: port must be greater than 0", stderr);
    return -1;
  }

  // char ip[INET_ADDRSTRLEN];
  // size_t ip_len = strlen(host);
  // strncpy(ip, host, ip_len);
  // ip[ip_len+1] = '\0';

  int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  struct sockaddr_in dest_addr;
  memset(&dest_addr, 0, sizeof(struct sockaddr_in));
  dest_addr.sin_family = AF_INET;
  dest_addr.sin_port = htons(port);
  inet_pton(AF_INET, host, &dest_addr.sin_addr);
  int retries = 0;

  if (inet_pton(AF_INET, host, &dest_addr.sin_addr) != 1) {
    fputs("Invalid IP address format.\n", stderr);
    return -1;
  }

  assert(config.base_timeout > 0);

  struct timeval tv;
  tv.tv_sec = config.base_timeout / 1000;
  tv.tv_usec = (config.base_timeout % 1000) * 1000;

  /* Construir pacote */
  PU_Header header;
  char packet[sizeof(header) + len];

  assert(config.max_retries > 0);

  while (retries < config.max_retries) {
    // Preencher header
    struct timeval now;
    gettimeofday(&now, NULL);

    header.timestamp = now.tv_sec * 1000000 + now.tv_usec;
    header.sequence = current_seq;
    header.flag = 0;

    /* Calcular checksum */
    memcpy(packet, &header, sizeof(header));
    memcpy(packet + sizeof(header), message, len);
    header.checksum = htons(pu_checksum_helper(packet, sizeof(header) + len));
    memcpy(packet, &header, sizeof(header));

    // Enviar
    ssize_t sent = sendto(sockfd, packet, sizeof(packet), 0,
                          (struct sockaddr *)&dest_addr, sizeof(dest_addr));
    if ((size_t)sent != sizeof(packet)) {
      perror("sendto() failed");
      return -1;
    }

    // Esperar ACK
    fd_set readset;
    FD_ZERO(&readset);
    FD_SET(sockfd, &readset);

    int ready = select(sockfd + 1, &readset, NULL, NULL, &tv);
    if (ready > 0) {

      PU_Header ack_header;
      struct sockaddr_in src_addr;
      socklen_t addr_len = sizeof(src_addr);

      ssize_t recvd = recvfrom(sockfd, &ack_header, sizeof(ack_header), 0,
                               (struct sockaddr *)&src_addr, &addr_len);

      if (recvd == sizeof(ack_header) && (PU_IS_ACK(ack_header.flag)) &&
          (uint64_t)ntohl(ack_header.sequence) == current_seq) {
        current_seq++;
        close(sockfd);
        return 0; // Sucesso
      }
    } else if (ready == 0) {
      retries++;
      fprintf(stderr, "Timeout, retrying (%d/%d)\n", retries,
              config.max_retries);
    } else {
      perror("select() failed");
      return -1;
    }
  }

  fprintf(stderr, "Max retries reached\n");
  return -1;
}

int pu_receive_message(char *buffer, int bufsize);

int main(int argc, char *argv[]) {

  /* Verificar argumentos */
  char *addr = argv[1];
  int port = atoi(argv[2]);

  // char *msg = argv[3];

  if (argc != 4) {
    perror("cliente [hostname] [port] [mensagem]");
    exit(EXIT_FAILURE);
  }

  /* Registar no servidor */
  if (pu_init_protocol(addr, port, PSK) < 0) {
    fputs("[ERROR] Failed to initialize PowerUDP\n", stderr);
    exit(EXIT_FAILURE);
  }

  struct sigaction sa = {.sa_handler = handle_sigint, .sa_flags = SA_RESTART};
  sigemptyset(&sa.sa_mask);
  sigaction(SIGINT, &sa, NULL);
  sigaction(SIGTERM, &sa, NULL);

  pthread_t multicast_listener;
  pthread_create(&multicast_listener, 0, thread_multicast_listener, NULL);

  // char destination[64];
  // snprintf(destination, sizeof(destination), "%s:%d", addr, port);
  // pu_send_message(destination, msg, strlen(msg));

  while (running) {
    pause();
    if (!running) break;
  }

  puts("Waiting for multicast listener to join...");
  running = 0;
  pthread_join(multicast_listener, NULL);

  /* Fechar registo no servidor */
  // pu_close_protocol();

  puts("Exited cleanly.");
  return 0;
}

static void handle_sigint() {
  puts("SIGINT RECIEVED");
  shutdown(global.mc_sock, SHUT_RDWR);
  close(global.mc_sock);
  running = 0;
}
