FROM alpine:latest
COPY bin/agent /usr/local/bin/agent
RUN apk add --no-cache iproute2
CMD ["agent"]
