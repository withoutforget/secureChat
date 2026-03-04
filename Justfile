[doc("Running golang application")]
@run:
    go run cmd/app/main.go
@build:
    go build
@rbuild:
    go build && ./test

@proto_gen:
    protoc --go_out=./pb/ --go-grpc_out=./pb/ service.proto --experimental_allow_proto3_optional

@build_all:
    go build -o bin/shard ./cmd/app
    go build -o bin/coordinator ./cmd/coordinator

@run-shard port="55000" mport="8080":
    go run ./cmd/app --p {{port}} --mp {{mport}}
@run-coordinator port="80" shards="55000":
    go run ./cmd/coordinator --p {{port}} --sp {{shards}}