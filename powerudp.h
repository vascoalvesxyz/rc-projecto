#ifndef _POWERUDP_
#define _POWERUDP_

#include <stdint.h>

/* Os clientes devem suportar o protocolo PowerUDP, cujas funcionalidades devem
 * ser suportadas em linha com a API descrita mais à frente.
 * O PowerUDP permitirá suportar as seguintes funcionalidades: 
1. Registo da aplicação cliente no servidor, com recurso a chave pré-configurada; 
2. Envio para o servidor de pedidos de alteração à configuração do protocolo ativa na rede; 
3. Envio e receção de mensagens UDP para outros hosts, com garantias de confiabilidade de acordo com a configuração ativa; */

typedef struct ConfigMessage {
    uint16_t base_timeout;          // 2 bytes, Tempo base para timeouts (ms)
    uint8_t enable_retransmission;  // 1 byte, 0 = Desativado, 1 = Ativado
    uint8_t enable_backoff;         // 1 byte, 0 = Desativado, 1 = Ativado
    uint8_t enable_sequence;        // 1 byte, 0 = Desativado, 1 = Ativado
    uint8_t max_retries;            // 1 byte, Número máximo de retransmissões
} ConfigMessage;

typedef struct RegisterMessage {
    char psk[64];   // Chave pré-definida para autenticação
} RegisterMessage;

// Inicializa a stack de comunicação e regista-se no servidor
int pu_init_protocol(const char *server_ip, int server_port, const char *psk);

// Termina a stack de comunicação e apaga o registo no servidor
void pu_close_protocol();

// Solicita mudança na configuração do protocolo ao servidor
int pu_request_protocol_config(int enable_retransmission, int enable_backoff, 
                            int enable_sequence, uint16_t base_timeout, uint8_t max_retries);

// Envia uma mensagem UDP
int pu_send_message(const char *destination, const char *message, int len);

// Recebe uma mensagem UDP
int pu_receive_message(char *buffer, int bufsize);

// Obtém estatísticas da última mensagem enviada
int pu_get_last_message_stats(int *retransmissions, int *delivery_time);

// Simula a perda de pacotes para testar retransmissões
void pu_inject_packet_loss(int probability);

#endif // !_POWERUDP_
