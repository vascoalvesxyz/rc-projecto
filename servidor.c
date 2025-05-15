/* O servidor é responsável por transmitir aos clientes uma nova configuração
 * para o PowerUDP via MULTICAST.
 *
 * Os clientes conectam via TCP.
 * */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>

int main(int argc, char *argv[] ) {

    char *addr = argv[1]
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
