# Proxy Server

A proxy server written in Go, currently supporting SOCKS5.

## Configuration

Copy the example configuration file:

```bash
cp config.example.yaml config.yaml
```

Edit `config.yaml` to customize your server settings.

Example configuration:

```yaml
servers:
  - name: socks5-main
    port: 1080
    type: socks5
    auth:
      status: true
      users:
        - username: admin
          password: "123456"
```

### Configuration Options

| Option        | Description                               |
| ------------- | ----------------------------------------- |
| `name`        | Server instance name                      |
| `port`        | Port to listen on                         |
| `type`        | Proxy protocol (`socks5`)                 |
| `auth.status` | Enable or disable password authentication |
| `auth.users`  | List of usernames and passwords           |

Multiple server instances can be configured under `servers`.

## Build

```bash
go build -o proxy cmd/main.go
```

## Run

Run using the default configuration file (`config.yaml`):

```bash
./proxy
```

Specify a configuration file:

```bash
./proxy -c config.example.yaml
```

Display available options:

```bash
./proxy -h
```

You can also run the project without building:

```bash
go run cmd/main.go -c config.example.yaml
```

## Testing

Test the SOCKS5 proxy with `curl`:

```bash
curl --proxy socks5h://127.0.0.1:1080 https://example.com
```

With username/password authentication:

```bash
curl --proxy socks5h://127.0.0.1:1080 \
     --proxy-user admin:123456 \
     https://example.com
```
