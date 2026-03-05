[doc("Run client")]
@client:
    go run cmd/app/main.go
[doc("Run server")]
@server:
    go run cmd/server/main.go
[doc("Lint code")]
@lint:
    golangci-lint run

[doc("windows client")]
@windows_client:
    -mkdir -p ./bin/
    GOOS=windows GOARCH=amd64 CGO_ENABLED=1 CC=x86_64-w64-mingw32-gcc \
        go build -o ./bin/app.exe ./cmd/app/main.go