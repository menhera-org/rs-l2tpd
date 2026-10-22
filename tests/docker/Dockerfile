FROM alpine:3.22
RUN apk add --no-cache iproute2 iputils
COPY network.sh /opt/network.sh
ENTRYPOINT ["sh", "/opt/network.sh"]
