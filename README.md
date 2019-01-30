# privacypass-rs

An implementation of Privacy Pass in Rust, compatible with [https://github.com/privacypass](https://github.com/privacypass).

Described in the post [https://kobigurk.com/2019/01/05/exploring-privacypass.html](https://kobigurk.com/2019/01/05/exploring-privacypass.html).

The *example-data* folder contains example configuration files for both the client and the server, a secret key for the server and a public commitment for the key to be used by the client.

## Building

The code relies on the [Apache Milagro Crypto Library](https://milagro.apache.org/), and is included as a submodule to the repository.

To be able to build and run, as described later, get the submodule:
```
git submodule update --init --recursive
```

## Docker

To use docker to build and run the privacypass-rs server, execute the following commands:

```
cd docker
docker build -t privacypass-server .
docker run -ti -p2416:2416 privacypass-server
```

## Running with example data

To execute with the example data, you can execute the following commands:

* For the server:
```
cd example_data
cargo run --bin privacypass-rs-server
```

* For the client:
```
cd example_data
cargo run --bin privacypass-rs-client
```

The example configuration files are configured for running both the server and client locally.


## Example public server

I'm running a test server at privacypass.kobi.one. To use it, change `example_data/server_settings.yaml` to point to the server as follows:

```
server_address: privacypass.kobi.one:2416
```
