/* O cliente comunica com outros clientes via PowerUDP.
 * O cliente comunica via TCP para pedir uma nova configuração ao Servidor.
 * */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <strings.h>
#include <unistd.h>

#include "powerudp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define MULTICAST_GROUP "239.255.42.99"
#define MULTICAST_PORT 4567

char psk[64];
ConfigMessage config; 

typedef struct {
} global_t;

global_t global;

/* PowerUDP */
int  pu_init_protocol(const char *server_ip, int server_port, const char *psk);
void pu_close_protocol();
int  pu_request_protocol_config(int enable_retransmission, int enable_backoff, int enable_sequence, uint16_t base_timeout, uint8_t max_retries);
int  pu_send_message(const char *destination, const char *message, int len);
int  pu_receive_message(char *buffer, int bufsize);
int  pu_get_last_message_stats(int *retransmissions, int *delivery_time);
void pu_inject_packet_loss(int probability);

/* Init protocol */
int pu_init_protocol(const char *server_ip, int server_port, const char *psk) {

  struct sockaddr_in sv_addr;
  int sv_sock;

  int udp_sock;

  /* TCP socket para comunicr com o server */
  sv_sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sv_sock < 0) {
    fputs("TCP socket creation failed", stderr);
    return -1;
  }

  /* address do servidor */
  sv_addr.sin_family = AF_INET;
  sv_addr.sin_port = htons(server_port);
  if (inet_pton(AF_INET, server_ip, &sv_addr.sin_addr) <= 0) {
    fputs("Invalid server address", stderr);
    goto exit_fail;
  }

  /* ligar ao servidor */
  if (connect(sv_sock, (struct sockaddr*) &sv_addr, sizeof(sv_addr)) < 0) {
    fputs("TCP connection failed", stderr);
    goto exit_fail;
  }

  /* Send PSK over TCP */
  if (send(sv_sock, psk, strlen(psk), 0) < 0) {
    fputs("PSK send failed", stderr);
    goto exit_fail;
  }

  return udp_sock;

exit_fail:
  close(sv_sock);
  return -1;
}

int main(int argc, char *argv[] ) {

  memset(&global, 0, sizeof(global_t));

  if (pu_init_protocol < 0) {
    fputs("[ERROR] Failed to initialize PowerUDP\n", stderr);
    exit(EXIT_FAILURE);
  }

  char *addr = argv[1];
  int port = atoi(argv[2]);

  if (argc != 3 || port < 1) {
    perror("servidor [hostname] [port]");
    exit(EXIT_FAILURE);
  }

  int sock;
  struct sockaddr_in multicast_addr;
  char message[] = "Hello, Multicast!";

  /* criar socket */
  sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (sock < 0) {
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
  if (setsockopt(sock, IPPROTO_IP, IP_MULTICAST_TTL, &enable, sizeof(enable)) < 0) {
    perror("Erro ao configurar multicast");
    exit(EXIT_FAILURE);
  }


  /* enviar mensagem multicast */
  int sendto_len = sendto(sock, message, strlen(message), 0, (struct sockaddr*)&multicast_addr, sizeof(multicast_addr));
  if (sendto_len < 0) {
    perror("Erro ao enviar mensagem");
    exit(1);
  }

  close(sock);
  return 0;
}
