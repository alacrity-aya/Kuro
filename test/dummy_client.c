#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

#define SERVER_IP "127.0.0.1"
#define PORT 8080
#define BUFFER_SIZE 65536 // 64KB per send

// 客户端程序，持续发送数据
int main() {
  int client_sock;
  struct sockaddr_in server_addr;
  char *buffer;
  long total_sent = 0;
  struct timeval start_time, current_time;

  printf("[CLIENT] PID: %d\n", getpid());
  printf("[CLIENT] 尝试连接到 %s:%d...\n", SERVER_IP, PORT);

  // 等待服务器启动 (重要: 脚本依赖于此睡眠时间来捕获 PID)
  int a;
  scanf("%d", &a);

  // 1. 创建套接字
  if ((client_sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    perror("[CLIENT] Socket creation error");
    return -1;
  }

  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(PORT);
  if (inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr) <= 0) {
    perror("[CLIENT] Invalid address/ Address not supported");
    close(client_sock);
    return -1;
  }

  // 2. 连接到服务器
  if (connect(client_sock, (struct sockaddr *)&server_addr,
              sizeof(server_addr)) < 0) {
    perror("[CLIENT] Connection failed. Is dummy_server running?");
    close(client_sock);
    return -1;
  }
  printf("[CLIENT] 连接成功，开始发送数据。\n");

  // 创建发送缓冲区
  buffer = (char *)malloc(BUFFER_SIZE);
  if (!buffer) {
    perror("[CLIENT] Failed to allocate buffer");
    close(client_sock);
    return -1;
  }
  memset(buffer, 'A', BUFFER_SIZE);

  gettimeofday(&start_time, NULL);

  // 3. 循环发送数据，直到被外部终止
  while (1) {
    ssize_t sent_bytes = send(client_sock, buffer, BUFFER_SIZE, 0);
    if (sent_bytes < 0) {
      perror("[CLIENT] Send failed");
      break;
    }
    total_sent += sent_bytes;

    // 打印速率（每 100MB 打印一次）
    if (total_sent >= 100 * 1024 * 1024) {
      gettimeofday(&current_time, NULL);
      double elapsed_time =
          (current_time.tv_sec - start_time.tv_sec) +
          (current_time.tv_usec - start_time.tv_usec) / 1000000.0;

      if (elapsed_time > 0) {
        double rate_mbps =
            (double)total_sent * 8 / (1024 * 1024 * elapsed_time);
        printf("[CLIENT] 累计发送: %.2f MB, 速率: %.2f Mbps\n",
               (double)total_sent / (1024 * 1024), rate_mbps);
      }

      // 重置计数器
      total_sent = 0;
      start_time = current_time;
    }
  }

  free(buffer);
  close(client_sock);
  return 0;
}
