#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <unistd.h>

#define PORT 12345
#define BUFFER_SIZE 65536

static double now_sec() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec + tv.tv_usec * 1e-6;
}

int main() {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    char buffer[BUFFER_SIZE];

    printf("[SERVER] PID: %d\n", getpid());

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("[SERVER] socket");
        exit(EXIT_FAILURE);
    }

    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        perror("[SERVER] setsockopt");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        perror("[SERVER] bind");
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 3) < 0) {
        perror("[SERVER] listen");
        exit(EXIT_FAILURE);
    }

    printf("[SERVER] Listening on port %d...\n", PORT);

    if ((new_socket = accept(server_fd, (struct sockaddr*)&address, (socklen_t*)&addrlen)) < 0) {
        perror("[SERVER] accept");
        exit(EXIT_FAILURE);
    }

    printf("[SERVER] Client connected, start receiving data...\n");

    long long total_bytes = 0;
    long long last_bytes = 0;
    double start = now_sec();
    double last_print = start;

    while (1) {
        ssize_t n = read(new_socket, buffer, BUFFER_SIZE);
        if (n <= 0)
            break;

        total_bytes += n;

        double t = now_sec();
        if (t - last_print >= 1.0) {
            long long interval_bytes = total_bytes - last_bytes;
            double bps = interval_bytes / (t - last_print);
            double mbps = (bps * 8) / 1e6;

            printf(
                "[SERVER] Total: %.2f MB  |  Speed: %.2f MB/s  (%.2f Mbps)\n",
                total_bytes / (1024.0 * 1024.0),
                bps / (1024.0 * 1024.0),
                mbps
            );

            last_bytes = total_bytes;
            last_print = t;
        }
    }

    double end = now_sec();
    double total_time = end - start;

    printf("[SERVER] Client disconnected.\n");
    printf(
        "[SERVER] Final total: %.2f MB in %.2f sec  =>  avg %.2f MB/s  (%.2f Mbps)\n",
        total_bytes / (1024.0 * 1024.0),
        total_time,
        (total_bytes / total_time) / (1024.0 * 1024.0),
        (total_bytes * 8.0 / total_time) / 1e6
    );

    close(new_socket);
    close(server_fd);
    return 0;
}
