#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define BUFFER_SIZE 1024

void print_error_and_exit(const char *message) {
    perror(message);
    exit(1);
}

void init_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl() {
    EVP_cleanup();
}

SSL_CTX* create_context() {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_server_method();  // Use TLS protocol
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        print_error_and_exit("Unable to create SSL context");
    }
    return ctx;
}

void configure_ssl_context(SSL_CTX *ctx, const char *cert_file, const char *key_file) {
    if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0) {
        print_error_and_exit("Error loading certificate");
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0) {
        print_error_and_exit("Error loading private key");
    }

    if (!SSL_CTX_check_private_key(ctx)) {
        print_error_and_exit("Private key does not match the certificate");
    }
}

int main() {
    char server_ip[16];
    int server_port;
    int sockfd, client_sock;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    SSL_CTX *ctx;
    SSL *ssl;
    char buffer[BUFFER_SIZE];

    // Prompt user for server details
    printf("Enter the server IP address (e.g., 127.0.0.1): ");
    scanf("%s", server_ip);
    printf("Enter the server port number: ");
    scanf("%d", &server_port);

    // Initialize OpenSSL
    init_openssl();

    // Create SSL context
    ctx = create_context();

    // Configure SSL context with certificate and private key
    configure_ssl_context(ctx, "server.crt", "server.key");

    // Create a TCP socket
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        print_error_and_exit("Error creating socket");
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(server_port);
    server_addr.sin_addr.s_addr = inet_addr(server_ip);

    // Bind socket to the address and port
    if (bind(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        print_error_and_exit("Error binding socket");
    }

    // Listen for incoming connections
    if (listen(sockfd, 10) < 0) {
        print_error_and_exit("Error listening on socket");
    }

    printf("SSL server listening on %s:%d...\n", server_ip, server_port);

    // Accept client connections in a loop
    while (1) {
        client_sock = accept(sockfd, (struct sockaddr*)&client_addr, &client_addr_len);
        if (client_sock < 0) {
            print_error_and_exit("Error accepting client connection");
        }

        // Create SSL object and associate with the client socket
        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client_sock);

        // Perform SSL handshake
        if (SSL_accept(ssl) <= 0) {
            print_error_and_exit("Error in SSL handshake");
        }

        // Receive message from client
        int bytes_received = SSL_read(ssl, buffer, sizeof(buffer) - 1);
        if (bytes_received <= 0) {
            print_error_and_exit("Error receiving data from client");
        }
        buffer[bytes_received] = '\0';  // Null-terminate the received message

        printf("Received message: %s\n", buffer);

        // Send the message back to the client (echo)
        if (SSL_write(ssl, buffer, bytes_received) <= 0) {
            print_error_and_exit("Error sending data to client");
        }
        printf("Echoed message to client\n");

        // Clean up
        SSL_free(ssl);
        close(client_sock);
    }

    // Clean up SSL context
    close(sockfd);
    SSL_CTX_free(ctx);
    cleanup_openssl();

    return 0;
}
