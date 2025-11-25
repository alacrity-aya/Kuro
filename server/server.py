import time
from concurrent import futures

import grpc

import helloworld_pb2
import helloworld_pb2_grpc


class GreeterServicer(helloworld_pb2_grpc.GreeterServicer):
    def SayHello(self, request, context):
        return helloworld_pb2.HelloReply(  # pyright: ignore[reportAttributeAccessIssue]
            message=f"Hello, {request.name}!"
        )


def serve():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    helloworld_pb2_grpc.add_GreeterServicer_to_server(GreeterServicer(), server)
    server.add_insecure_port("[::]:50051")
    server.start()
    print("Python gRPC server running on 50051")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        server.stop(0)


if __name__ == "__main__":
    serve()
