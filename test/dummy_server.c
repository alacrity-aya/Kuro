
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <unistd.h>

#define PORT 8080
#define BUFFER_SIZE 65536

int main() {
  int server_fd, new_socket;
  struct sockaddr_in address;
  int addrlen = sizeof(address);
  char buffer[BUFFER_SIZE] = {0};

  printf("[SERVER] PID: %d\n", getpid());

  if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
    perror("[SERVER] socket failed");
    exit(EXIT_FAILURE);
  }

  // 允许地址重用
  if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &(int){1},
                 sizeof(int))) {
    perror("[SERVER] setsockopt failed");
    exit(EXIT_FAILURE);
  }

  address.sin_family = AF_INET;
  address.sin_addr.s_addr = INADDR_ANY;
  address.sin_port = htons(PORT);

  if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
    perror("[SERVER] bind failed");
    exit(EXIT_FAILURE);
  }
  if (listen(server_fd, 3) < 0) {
    perror("[SERVER] listen failed");
    exit(EXIT_FAILURE);
  }

  printf("[SERVER] 监听端口 %d...\n", PORT);
  if ((new_socket = accept(server_fd, (struct sockaddr *)&address,
                           (socklen_t *)&addrlen)) < 0) {
    perror("[SERVER] accept failed");
    exit(EXIT_FAILURE);
  }
  printf("[SERVER] 客户端连接成功！开始接收数据。\n");

  // 持续接收数据，直到连接关闭
  while (read(new_socket, buffer, BUFFER_SIZE) > 0) {
    // 接收数据，但不处理，主要目的是让连接保持活跃
  }

  printf("[SERVER] 客户端断开连接或发送停止。\n");
  close(new_socket);
  close(server_fd);
  return 0;
}
