# NATCat

NATCat is a single-binary NAT mapping console with an embedded WebUI. It is designed for running on a LAN host behind a NAT router and keeping a stable public mapping visible for TCP and UDP services.

The project is written in Go and ships the frontend as embedded static assets, so deployment is one binary plus one JSON data file.

中文快速上手: [docs/quick-start.zh-CN.md](docs/quick-start.zh-CN.md)

## Features

- Built-in authenticated WebUI
- Multi-instance TCP and UDP mapping management
- TCP keep-alive over HTTP
- UDP keep-alive over HTTP/3 QUIC
- STUN-based public address probing
- Configurable STUN, HTTP, and QUIC server lists
- Public mapping confirmation to avoid transient wrong STUN results
- TCP reachability checks with latency display
- Notification hook scripts with public IP and port variables
- Optional Linux interface binding and fwmark support
- Systemd-friendly single-binary deployment

## Build

NATCat requires Go 1.26 or newer.

```sh
go test ./...
go build -o natcat ./cmd/natcat
```

Cross-build a static Linux amd64 binary:

```sh
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o natcat-linux ./cmd/natcat
```

## Run

```sh
./natcat --listen 0.0.0.0:8080
```

On first run, NATCat creates a random admin password and prints it to the terminal.

Choose the first password explicitly:

```sh
NATCAT_SETUP_PASSWORD='change-me' ./natcat
```

Use a custom data file:

```sh
./natcat --data ./natcat.json
```

## Change Password

```sh
./natcat password --data ./natcat.json --password 'new-password'
```

The command also accepts the password as a positional value:

```sh
./natcat password --data ./natcat.json 'new-password'
```

If the service is already running, restart it after changing the password.

## Systemd

Copy the binary and service file:

```sh
sudo mkdir -p /opt/natcat /var/lib/natcat
sudo cp ./natcat-linux /opt/natcat/natcat
sudo chmod +x /opt/natcat/natcat
sudo cp deploy/natcat.service /etc/systemd/system/natcat.service
sudo systemctl daemon-reload
sudo systemctl enable --now natcat
```

View logs:

```sh
journalctl -u natcat -f
```

The sample service listens on `0.0.0.0:8080` and stores data in `/var/lib/natcat/data.json`.

## Notification Scripts

Notification scripts run only when the confirmed public mapping changes.

These variables are replaced before execution:

```sh
$NATCAT_PUBLIC_IP
$NATCAT_PUBLIC_PORT
$NATCAT_PUBLIC_ENDPOINT
```

They are also available as environment variables, together with:

```sh
NATCAT_INSTANCE_ID
NATCAT_INSTANCE_NAME
NATCAT_PROTOCOL
NATCAT_PRIVATE_ADDRESS
NATCAT_PRIVATE_PORT
```

Example:

```sh
curl "https://example.com/hook?endpoint=$NATCAT_PUBLIC_ENDPOINT"
```

## Public Mapping Confirmation

Each instance has a confirmation count. The default is `2`.

When STUN returns a public mapping, NATCat requires the same `IP:port` result to be confirmed repeatedly before publishing it to the UI or running notification scripts. Set the count to `1` to use a single STUN result.

## Notes

- NATCat does not provide traffic forwarding. It only maintains and reports NAT mappings.
- UDP services that do not reply cannot be universally tested from the outside by NATCat.
- Interface binding and fwmark support may require root privileges on Linux.
- Do not commit your `data.json`; it contains admin credential hashes and instance configuration.

## License

NATCat is released under the MIT License. See `LICENSE`.
