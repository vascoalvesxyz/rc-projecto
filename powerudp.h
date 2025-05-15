#ifndef _POWERUDP_
#define _POWERUDP_

#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>

/* Os clientes devem suportar o protocolo PowerUDP, cujas funcionalidades devem
 * ser suportadas em linha com a API descrita mais à frente.
 * O PowerUDP permitirá suportar as seguintes funcionalidades:
1. Registo da aplicação cliente no servidor, com recurso a chave
pré-configurada;
2. Envio para o servidor de pedidos de alteração à configuração do protocolo
ativa na rede;
3. Envio e receção de mensagens UDP para outros hosts, com garantias de
confiabilidade de acordo com a configuração ativa; */

/* Definição dos flags (usando bits distintos) */
#define PU_DATA     0b10000000  // Bit 7 (1 << 7)
#define PU_ACK      0b01000000  // Bit 6 (1 << 6)

/* Macros para verificar os flags */
#define PU_IS_DATA(f)  ((f) & PU_DATA)
#define PU_IS_ACK(f)   ((f) & PU_ACK)

/* Macros para definir os flags */
#define PU_SET_DATA(f) ((f) |= PU_DATA)
#define PU_SET_ACK(f)  ((f) |= PU_ACK)

typedef struct {
  uint64_t timestamp;    // Timestamp em microssegundos
  uint32_t sequence;     // Número de sequência para controle
  uint16_t checksum;     // Checksum customizado
  uint8_t flag;
} PU_Header;

typedef struct {
    uint16_t base_timeout;          // 2 bytes, Tempo base para timeouts (ms)
    uint8_t enable_retransmission;  // 1 byte, 0 = Desativado, 1 = Ativado
    uint8_t enable_backoff;         // 1 byte, 0 = Desativado, 1 = Ativado
    uint8_t enable_sequence;        // 1 byte, 0 = Desativado, 1 = Ativado
    uint8_t max_retries;            // 1 byte, Número máximo de retransmissões
} PU_ConfigMessage;

typedef struct {
    char psk[64];   // Chave pré-definida para autenticação
} PU_RegisterMessage;

// Inicializa a stack de comunicação e regista-se no servidor
int pu_init_protocol(const char *server_ip, int server_port, const char *psk);

// Termina a stack de comunicação e apaga o registo no servidor
void pu_close_protocol();

// Solicita mudança na configuração do protocolo ao servidor
int pu_request_protocol_config(PU_ConfigMessage new_config);

// Envia uma mensagem UDP
int pu_send_message(const char *destination, const char *message, int len);

// Recebe uma mensagem UDP
int pu_receive_message(char *buffer, int bufsize);

// Obtém estatísticas da última mensagem enviada
int pu_get_last_message_stats(int *retransmissions, int *delivery_time);

// Simula a perda de pacotes para testar retransmissões
void pu_inject_packet_loss(int probability);

static inline uint16_t pu_checksum_helper(const void *data, size_t len) {
    const uint8_t *bytes = (uint8_t*) data;
    uint32_t sum = 0;
    for (size_t i = 0; i < len; i++) {
        sum += bytes[i];
    }
    return (uint16_t)(sum & 0xFFFF);
}

#endif // !_POWERUDP_
