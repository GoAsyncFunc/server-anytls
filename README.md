# server-anytls

AnyTLS server node for V2Board/UniProxy, built with Sing-box.

## Features

- **Protocol**: AnyTLS
- **Core**: Sing-box
- **Integration**: Works with V2Board/UniProxy API for user management and traffic reporting.

## Build

```bash
go build -v -o anytls-node ./cmd/server
```

## Usage

```bash
./anytls-node --api "https://your-panel.com" --token "your-node-token" --node 1
```

## Docker

```bash
docker build -f build/package/Dockerfile -t anytls-node .
```
