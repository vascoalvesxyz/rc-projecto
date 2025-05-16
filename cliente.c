/* O cliente comunica com outros clientes via PowerUDP.
 * O cliente comunica via TCP para pedir uma nova configuração ao Servidor.
 * */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <strings.h>
#include <unistd.h>
#include <assert.h>

#include "powerudp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include <stdbool.h>

#define SV_IP   "193.137.101.1"
#define SV_PORT 443

#define MULTICAST_GROUP "239.255.0.1"
#define MULTICAST_PORT 54321

#define PSK     "337b8d2c1e132acd75171f1acf0e73b20bc9541720d5003813f59ef0ad51f86f"

PU_ConfigMessage config = {0}; 
static uint64_t current_seq = 0;

typedef struct {
  struct sockaddr_in sv_addr;
  int sv_sock;
} global_t;

global_t global;

/* PowerUDP */
int  pu_init_protocol(const char *server_ip, int server_port, const char *psk);
void pu_close_protocol();

int  pu_request_protocol_config(PU_ConfigMessage new_config);
int  pu_send_message(const char *destination, const char *message, int len);
int  pu_receive_message(char *buffer, int bufsize);
int  pu_get_last_message_stats(int *retransmissions, int *delivery_time);
void pu_inject_packet_loss(int probability);

static bool config_is_set() {

  PU_ConfigMessage empty_config = {0};
  if (memcmp((void*) &empty_config, (void*) &config, sizeof(PU_ConfigMessage))) {
    return true;
  }
  
  return false;
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
  global.sv_addr.sin_family = AF_INET;
  global.sv_addr.sin_port = htons(server_port);
  if (inet_pton(AF_INET, server_ip, &global.sv_addr.sin_addr) <= 0) {
    fputs("Invalid server address", stderr);
    close(global.sv_sock);
    return -1;
  }

  /* ligar ao servidor */
  if (connect(global.sv_sock, (struct sockaddr*) &sv_addr, sizeof(sv_addr)) < 0) {
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
  int recvlen = read(global.sv_sock, &resposta_serializada, sizeof(PU_ConfigMessage));
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
  }
  else if (recvlen < (int) sizeof(PU_ConfigMessage)) {
    fputs("Recieved malformed config.", stderr);
    close(global.sv_sock);
    return -1;
  }

  memcpy(&config, resposta_serializada, sizeof(PU_ConfigMessage) );
  puts("Successfuly retrieved config!");
  return 0;
}

int pu_send_message(const char *destination, const char *message, int len) {

  const char* host = destination;
  char* seperator = strchr(host, ':');
  if (seperator == NULL) {
    fputs("[ERROR] pu_send_message: does not contain ':' seperator.", stderr);
    return -1;
  }

  int port = atoi(seperator+1);
  if (port <= 0) {
    fputs("[ERROR] pu_send_message: port must be greater than 0", stderr);
    return -1;
  }

  int retries = 0;

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
    // gettimeofday(&now, NULL);

    header.timestamp = now.tv_sec * 1000000 + now.tv_usec;
    header.sequence = current_seq;
    header.flag = 0;

    /* Calcular checksum */
    memcpy(packet, &header, sizeof(header));
    memcpy(packet + sizeof(header), message, len);
    header.checksum = htobe16(pu_checksum_helper(packet, sizeof(header) + len));
    memcpy(packet, &header, sizeof(header));

    // Enviar
    ssize_t sent = sendto(sockfd, packet, sizeof(packet), 0,
                          (struct sockaddr*)dest_addr, sizeof(*dest_addr));
    if (sent != sizeof(packet)) {
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

      ssize_t recvd = recvfrom(sockfd, &ack_header, sizeof(ack_header), 0, (struct sockaddr*)&src_addr, &addr_len);

      if (recvd == sizeof(ack_header) && 
        (PU_IS_ACK(ack_header.flag)) && 
        be32toh(ack_header.sequence) == current_seq) {
        current_seq++;
        return 0; // Sucesso
      }
    } else if (ready == 0) {
      retries++;
      fprintf(stderr, "Timeout, retrying (%d/%d)\n", retries, config.max_retries);
    } else {
      perror("select() failed");
      return -1;
    }
  }

  fprintf(stderr, "Max retries reached\n");
  return -1;
}

int  pu_receive_message(char *buffer, int bufsize);

int main(int argc, char *argv[] ) {

  /* Verificar argumentos */
  char *addr = argv[1];
  int port = atoi(argv[2]);

  // char *msg = argv[2];

  if (argc != 4) {
    perror("cliente [hostname] [port] [mensagem]");
    exit(EXIT_FAILURE);
  }

  /* Registar no servidor */ 
  if (pu_init_protocol(addr, port, PSK) < 0) {
    fputs("[ERROR] Failed to initialize PowerUDP\n", stderr);
    exit(EXIT_FAILURE);
  }

  // pu_send_message(addr, , int len)
  /* Fechar registo no servidor */
  // pu_close_protocol();

  return 0;
}
