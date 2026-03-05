FROM golang:1.24-alpine AS securechat-builder

WORKDIR /app
COPY go.mod go.sum ./
COPY vendor/ vendor/
COPY cmd/server/ cmd/server/

RUN go build -mod=vendor -o server ./cmd/server/main.go

FROM alpine:3.21 AS securechat-runner

WORKDIR /app
COPY --from=securechat-builder /app/server .

EXPOSE 8080
CMD ["./server"]