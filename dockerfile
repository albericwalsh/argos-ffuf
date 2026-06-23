FROM golang:alpine

RUN apk add --no-cache git && \
    go install github.com/ffuf/ffuf/v2@latest

ENV PATH="/root/go/bin:${PATH}"

ENTRYPOINT ["ffuf"]