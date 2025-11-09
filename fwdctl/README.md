# fwdctl

`fwdctl` is a small CLI designed to make it easy to experiment with firewood locally.

## Building locally

```sh
cargo build --release --bin fwdctl
```

To use

```sh
./target/release/fwdctl -h
```

## Supported commands

* `fwdctl create`: Create a new firewood database.
* `fwdctl get`: Get the code associated with a key in the database.
* `fwdctl insert`: Insert a key/value pair into the generic key/value store.
* `fwdctl delete`: Delete a key/value pair from the database.
* `fwdctl root`: Get the root hash of the key/value trie.
* `fwdctl dump`: Dump the contents of the key/value store.

## Health service

`fwdctl` starts a lightweight HTTP service alongside every invocation. The service exposes
two endpoints:

* `GET /health/live` – returns `200 OK` while the process is running.
* `GET /health/ready` – returns `200 OK` when the CLI has initialised.

The service listens on `0.0.0.0:8080` by default. Override the port by setting the
`FWDCTL_HEALTH_PORT` environment variable. Assign the variable to `0` to disable the health
service entirely.

## Examples

* fwdctl create

```sh
# Check available options when creating a database, including the defaults.
$ fwdctl create -h
# Create a new, blank instance of firewood using the default name "firewood.db".
$ fwdctl create firewood.db
```

* fwdctl get KEY

```sh
# Get the value associated with a key in the database, if it exists.
fwdctl get KEY
```

* fwdctl insert KEY VALUE

```sh
# Insert a key/value pair into the database.
fwdctl insert KEY VALUE
```

* fwdctl delete KEY

```sh
# Delete a key from the database, along with the associated value.
fwdctl delete KEY
```

## Running in Docker

A multi-stage `Dockerfile` is provided alongside the crate. Build the image with:

```sh
docker build -t fwdctl:local -f fwdctl/Dockerfile .
```

Run the CLI inside the container while exposing the health service (adjust ports as
needed):

```sh
docker run --rm -p 8080:8080 fwdctl:local --help
```

Configure the health server port at runtime with `FWDCTL_HEALTH_PORT`:

```sh
docker run --rm -e FWDCTL_HEALTH_PORT=9090 -p 9090:9090 fwdctl:local create --db /data/firewood.db
```

The container runs the binary as a non-root user and includes a Docker `HEALTHCHECK` that
targets the readiness endpoint.
