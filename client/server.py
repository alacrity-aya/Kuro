# 导入生成的 Protobuf 消息和 gRPC 存根
from time import sleep

import grpc
from google.protobuf.empty_pb2 import Empty  # 导入 Empty 消息

import kuro_pb2 as pb2
import kuro_pb2_grpc as pb2_grpc


def run():
    # 建立一个到服务端的连接。
    # 替换 'localhost:50051' 为你的 gRPC 服务端的实际地址和端口。
    with grpc.insecure_channel("localhost:50051") as channel:
        # 创建客户端存根 (Stub)
        stub = pb2_grpc.RateCalculatorStub(channel)

        print("--- 正在调用 CalcRate()... ---")
        try:
            while True:
                sleep(2)
                # 调用 rpc 方法。CalcRate() 接收一个 Empty 对象作为请求。
                response: pb2.FlowRate = stub.CalcRate(Empty())

                # 处理服务端返回的 FlowRate 消息
                print("✅ 成功接收到 FlowRate:")
                print(f"  Accepted Bytes Rate: {response.accepted_bytes_rate}")
                print(f"  Dropped Bytes Rate: {response.dropped_bytes_rate}")
                print(f"  Accepted Packets Rate: {response.accepted_packets_rate}")
                print(f"  Dropped Packets Rate: {response.dropped_packets_rate}")

                # 验证数据的类型 (它们在 Protobuf 中被定义为 double，在 Python 中对应 float)
                print(
                    f"  类型检查: accepted_bytes_rate 是 {type(response.accepted_bytes_rate)}"
                )

        except grpc.RpcError as e:
            print(f"❌ 调用失败: 状态码={e.code()}, 详情={e.details()}")


if __name__ == "__main__":
    run()
