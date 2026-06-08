# Contributing

Thanks for improving NATCat.

## Development

Run tests before sending changes:

```sh
go test ./...
```

Build the local binary:

```sh
go build -o natcat ./cmd/natcat
```

The WebUI is embedded from `web/dist`, so changes to files in that directory require rebuilding the Go binary.

## Pull Requests

- Keep changes focused.
- Include tests for core behavior changes.
- Do not commit generated binaries, local data files, screenshots, logs, or secrets.
- Update `README.md` when behavior or configuration changes.

## Security

Do not include credentials, API tokens, cloud secrets, router passwords, or real production data in issues, pull requests, logs, or screenshots.
