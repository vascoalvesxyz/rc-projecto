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
#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L
#include "powerudp.h"
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

#define SV_IP "193.137.101.1"
#define SV_PORT 443

#define MULTICAST_GROUP "239.255.0.1"
#define MULTICAST_PORT 54321

#define PU_PORT 1337

#define PSK "337b8d2c1e132acd75171f1acf0e73b20bc9541720d5003813f59ef0ad51f86f"

#define DEBUG

typedef struct {
  int sv_sock;
  int mc_sock;
  int pu_sock;
  int dest_sock;
} global_t;

static global_t global;
static PU_ConfigMessage config = {0};
static uint64_t current_seq = 0;
static volatile sig_atomic_t running = 1;
int packet_loss_percent = 0;

/* Helpers */
static void *thread_multicast_listener(void *arg);
static void *thread_receive_loop(void *arg);
static bool setup_multicast(char* group, int port);
static bool setup_pu_listener(int port);
static void handle_sigint();
static char* parse_destination(const char* src, int *port_ptr);

/* PowerUDP */
int pu_init_protocol(const char *server_ip, int server_port, const char *psk);
void pu_close_protocol();

int pu_request_protocol_config(PU_ConfigMessage new_config);
int pu_send_message(const char *destination, const char *message, int len);
int pu_receive_message(char *buffer, int bufsize);

int pu_get_last_message_stats(int *retransmissions, int *delivery_time);
void pu_inject_packet_loss(int probability);

static void *thread_receive_loop(void *arg) {
  (void)arg;
  char buf[2048];

  while (running) {
    int n = pu_receive_message(buf, sizeof(buf));
    if (n > 0) {
      buf[n] = '\0'; // garantir que termina com null
      printf("\n[Recebido] %s\n> ", buf);
      fflush(stdout);
      continue;
    } else {
      /* NAK enviado */
    }
  }

  puts("[PowerUDP Listener] Exited.");
  pthread_exit(NULL);
}

static void *thread_multicast_listener(void *arg) {
  (void)arg;

  assert(global.mc_sock > 0);

  PU_ConfigMessage new_config;
  struct sockaddr_in src_addr;
  socklen_t addr_len = sizeof(src_addr);

  while (running) {
    ssize_t len = recvfrom(global.mc_sock, &new_config, sizeof(new_config), 0, (struct sockaddr *)&src_addr, &addr_len);
    if (!running) break;

    if (len != sizeof(new_config)) {
      fprintf(stderr, "[Multicast Listener] Received incomplete config (%zd/%zu bytes)\n", len, sizeof(new_config));
      continue;
    }

    /* Process multicast message */
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &src_addr.sin_addr, ip_str, sizeof(ip_str));
    printf("[Multicast Listener] Received multicast from %s:%d\n", ip_str,
           ntohs(src_addr.sin_port));
    printf("[Multicast Listener] New config: "
           "Timeout=%d\tBackoff=%d\tRetransmission=%d\tSequence=%d\tMax_"
           "Retries=%d\n",
           new_config.base_timeout, new_config.enable_backoff,
           new_config.enable_retransmission, new_config.enable_sequence,
           new_config.max_retries);

    memcpy(&config, &new_config, sizeof(config));
  }

  if (global.mc_sock > 0)
    close(global.mc_sock);
  pthread_exit(NULL);
}

static bool setup_multicast(char* group, int port) {
  /* multicast sock */
  global.mc_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (global.mc_sock < 0) {
    perror("[Multicast Listener] Multicast socket creation failed");
    return false;
  }

  /* reuse */
  int reuse = 1;
  if (setsockopt(global.mc_sock, SOL_SOCKET, SO_REUSEADDR, &reuse,
                 sizeof(reuse)) < 0) {
    perror("[Multicast Listener] setsockopt(SO_REUSEADDR) failed");
    close(global.mc_sock);
    return false;
  }

  /* usar grupo predefinido */
  struct sockaddr_in addr = {
    .sin_family = AF_INET,
    .sin_port = htons(port),
    .sin_addr.s_addr = INADDR_ANY
  };

  /* bind */
  if (bind(global.mc_sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    perror("[Multicast Listener] Multicast bind failed");
    close(global.mc_sock);
    return false;
  }

  /* mreq */
  struct ip_mreq mreq;
  mreq.imr_multiaddr.s_addr = inet_addr(group);
  mreq.imr_interface.s_addr = INADDR_ANY;
  if (setsockopt(global.mc_sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq,
                 sizeof(struct ip_mreq)) < 0) {
    perror("[Multicast Listener] Join multicast group failed");
    close(global.mc_sock);
    return false;
  }

  puts("[Multicast Listener] Joined multicast group!");
  return true;
}

static bool setup_pu_listener(int port) {

  /* socket receive message */
  global.pu_sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (global.pu_sock < 0) {
    perror("pu socket creation failed");
    return false;
  }

  // int reuse = 1;
  // setsockopt(global.pu_sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
  struct sockaddr_in addr_sock = {.sin_family = AF_INET, .sin_port = htons(port), .sin_addr.s_addr = INADDR_ANY};
  if (bind(global.pu_sock, (struct sockaddr *)&addr_sock, sizeof(addr_sock)) < 0) {
    perror("bind failed");
    close(global.pu_sock);
    return false;
  }

  return true;
}

static void handle_sigint() {
  running = 0;
}

static char* parse_destination(const char* src, int *port_ptr) {

  /* Dar parse ao destino */
  char *host = (char*) src;
  char *seperator = strchr(host, ':');
  if (seperator == NULL) {
    fputs("Destino não contem ':'\n", stderr);
    return NULL;
  }
  *seperator = '\0';

  /* Dar parse ao port */
  int port = atoi(seperator + 1);
  if (port <= 0 || port >= 65535) {
    fputs("Port inválido.\n", stderr);
    return NULL;
  }

  /* return */
  *port_ptr = port;
  return host;
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
  struct sockaddr_in sv_addr = {.sin_family = AF_INET,
    .sin_port = htons(server_port)};

  if (inet_pton(AF_INET, server_ip, &sv_addr.sin_addr) <= 0) {
    fputs("Invalid server address", stderr);
    close(global.sv_sock);
    return -1;
  }

  /* ligar ao servidor */
  if (connect(global.sv_sock, (struct sockaddr *)&sv_addr, sizeof(sv_addr)) <
    0) {
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
  close(global.sv_sock);
  return 0;
}

void pu_close_protocol() {
  puts("Closing protocol...");
  shutdown(global.mc_sock, SHUT_RDWR);
  shutdown(global.pu_sock, SHUT_RDWR);
  close(global.mc_sock);
  close(global.pu_sock);
}

int pu_send_message(const char *destination, const char *message, int len) {

  int port = 0;
  char *host = parse_destination(destination, &port);
  if (host == NULL) return -1;

  /* abrir socket de destino etc, etc */
  int destino_fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (destino_fd < 0) {
    puts("Falha ao conectar ao destino. O IP está correcto?");
    return -1;
  }

  struct sockaddr_in dst = {0};
  dst.sin_family = AF_INET;
  dst.sin_port   = htons(port);
  if (inet_pton(AF_INET, host, &dst.sin_addr) != 1) {
    puts("IP inválido?");
    close(destino_fd);
    return -1;
  }

  if (connect(destino_fd, (struct sockaddr*)&dst, sizeof(dst)) < 0) {
    perror("connect: ");  /* diz exatamente o erro */
    close(destino_fd);
    return -1;
  }

  puts("Destino conectado com sucesso!");

  /* preencher pacote */
  PU_Header header = {0};
  header.timestamp = pu_timestamp_helper();
  header.sequence  = current_seq;
  header.flag      = 0;

  /* serializar */
  char packet_serial[sizeof(header) + len];
  /* copiar header e payload */
  memcpy(packet_serial, &header, sizeof(header));
  memcpy(packet_serial + sizeof(header), message, len);
  /* calcular chekcsum e copiar header outra vez */
  header.checksum  = pu_checksum_helper(packet_serial, sizeof(header) + len);
  memcpy(packet_serial, &header, sizeof(header));

  int       retries = 0;
  PU_Header resposta = {0};
  while (retries < config.max_retries) {
    /* envio do packet */
    write(destino_fd, packet_serial, sizeof(header)+len);
    read(destino_fd, &resposta, sizeof(PU_Header)); /* esperar resposta */

    /* berificar que recebemos um ACK */
    if (PU_IS_ACK(resposta.flag)) {
      puts("Mensagem enviada com sucesso!");
      current_seq++; // sequencia enviada com sucesso
      close(destino_fd);
      return 0;
    } 
    else if (PU_IS_NAK(resposta.flag)) {
      printf("Mensagem rejeitada... renviando... (%d/%d)\n", retries, config.max_retries);
    } else {
      printf("Resposta inválida?... desistindo... \n");
      close(destino_fd);
      return -1;
    }

    retries++;
  } 

  close(destino_fd);
  puts("Tentativa máxima excedida");
  return -1;
}

int pu_receive_message(char *buffer, int bufsize) {

  struct sockaddr_in sender;
  socklen_t sender_len = sizeof(sender);

  char packet[sizeof(PU_Header) + bufsize];

  ssize_t len = recvfrom(global.pu_sock, packet, sizeof(packet), 0, (struct sockaddr *)&sender, &sender_len);

  if (len <= 0) return -1;

  if (len < (ssize_t)sizeof(PU_Header)) {
    fprintf(stderr, "Pacote incompleto (%zd bytes)\n", len);
    return -1;
  }

  PU_Header header;
  memcpy(&header, packet, sizeof(PU_Header));

  uint32_t received_seq = header.sequence; 
  uint16_t received_checksum = header.checksum;

  /* verificar chekcsum */
  header.checksum = 0;
  memcpy(packet, &header, sizeof(PU_Header));
  bool valid_checksum = (received_checksum == pu_checksum_helper(packet, len));

  /* sequencia */
  static uint32_t expected_seq = 0;
  bool valid_sequence = true;

  if (config.enable_sequence) {
    valid_sequence = (received_seq == expected_seq);
  }

  PU_Header response = {
    .sequence = received_seq, 
    .timestamp = header.timestamp,
    .flag = 0
  };

  /* Injectar perda de pacotes */
  if (packet_loss_percent > 0) {
    int r = 1+(rand()%100);
    if (r <= packet_loss_percent) 
      puts("Packet loss foi injectado!");
    valid_sequence = (r > packet_loss_percent) ;
  }

  /* Se o packet for valido, enviar ACK */
  if (valid_checksum && valid_sequence) {
    PU_SET_ACK(response.flag);
    int payload_len = len - sizeof(PU_Header);
    memcpy(buffer, packet + sizeof(PU_Header), payload_len);

    if (config.enable_sequence) 
      expected_seq++; 

    sendto(global.pu_sock, &response, sizeof(response), 0, (struct sockaddr *)&sender, sender_len);
    return payload_len;
  } 
  /* Se o packet for invalido, enviar NAK */
  else {
    #ifdef DEBUG
    puts("[DEBUG] recieve message: NAK enviado.");
    #endif /* ifdef DEBUG */
    PU_SET_NAK(response.flag);
    sendto(global.pu_sock, &response, sizeof(response), 0, (struct sockaddr *)&sender, sender_len);
    return -1;
  }

  return -1;
}

void pu_inject_packet_loss(int probability) {
  assert(probability >= 0 && probability <= 100);
  packet_loss_percent = probability;
}

int main(int argc, char *argv[]) {

  if (argc != 3) {
    puts("cliente [server hostname:port] [client port]");
    exit(EXIT_FAILURE);
  }


  int sv_port = 0;
  char *sv_host = parse_destination(argv[1], &sv_port);
  if (sv_host == NULL) {
    puts("cliente [server hostname:port] [client port]");
    exit(EXIT_FAILURE);
  }

  int my_port = atoi(argv[2]);


  /* Registar no servidor */
  if (  pu_init_protocol(sv_host, sv_port, PSK) < 0 
    || !setup_multicast(MULTICAST_GROUP, MULTICAST_PORT)
    || !setup_pu_listener(my_port) 
  ) {
    exit(EXIT_FAILURE);
  }

  pu_inject_packet_loss(30);

  /* Criar thread listeners */ 
  pthread_t multicast_listener;
  pthread_create(&multicast_listener, 0, thread_multicast_listener, NULL);
  pthread_t recv_thread;
  pthread_create(&recv_thread, NULL, thread_receive_loop, NULL);

  /* Handle sigint */
  struct sigaction sa = {.sa_handler = handle_sigint};
  sigemptyset(&sa.sa_mask);
  sigaction(SIGINT, &sa, NULL);
  sigaction(SIGTERM, &sa, NULL);

  char line[256];
  while (running) {

    printf("> ");
    if (!fgets(line, sizeof(line), stdin))
      break;

    if (strncmp(line, "msg ", 4) == 0) {
      char ipport[64], msg[192];
      if (sscanf(line + 4, "%63s %[^\n]", ipport, msg) == 2) {
        pu_send_message(ipport, msg, strlen(msg));
      } else {
        printf("Uso: msg <ip:port> <mensagem>\n");
      }
    } else if (strncmp(line, "sair", 4) == 0) {
      break;
    } else {
      printf("Comando inválido. Usa: msg <ip:port> <mensagem> ou sair\n");
    }

  }

  pu_close_protocol();

  puts("Waiting for multicast listener to join...");
  pthread_join(multicast_listener, NULL);
  puts("Waiting for power udp listener to join...");
  pthread_join(recv_thread, NULL);

  /* Fechar registo no servidor */
  // pu_close_protocol();

  puts("Exited cleanly.");
  return 0;
}
