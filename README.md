# lbcwallet

lbcwallet implements HD Wallet functionality which conforms to
[BIP0032](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki),
[BIP0043](https://github.com/bitcoin/bips/blob/master/bip-0043.mediawiki),
and [BIP0044](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki).

## Security

We take security seriously. Please contact [security](mailto:security@lbry.com) regarding any security issues.
Our PGP key is [here](https://lbry.com/faq/pgp-key) if you need it.

## Build from Source Code

Requires [Go](http://golang.org) 1.19 or newer.  Install Go according to its [installation instructions](http://golang.org/doc/install).

``` sh
git clone https://github.com/lbryio/lbcwallet
cd lbcwallet
go build .
```

## **lbcd** & **lbcwallet**

`lbcwallet` is not an SPV client and requires connecting to a `lbcd` node for asynchronous blockchain queries and notifications over websockets.

lbcwallet can serve wallet related RPCs and proxy lbcd RPCs to the assocated lbcd. It's sufficient for a user to connect just the **lbcwallet** instead of both.

``` mermaid
sequenceDiagram
    actor C as lbcctl
    participant W as lbcwallet (port: 9244)
    participant D as lbcd (port: 9245)

    rect rgb(200,200,200)
    Note over C,W: lbcctl --wallet balance
    C ->>+ W: getbalance
    W -->>- C: response
    end

    rect rgb(200,200,200)
    Note over C,D: lbcctl --wallet getblockcount (lbcd RPC service proxied by lbcwallet)
    C ->>+ W: getblockcount
    W ->>+ D: getblockcount
    D -->>- W: response
    W -->>- C: response
    end
```

## Getting Started

Create a new wallet with a randomly generated seed or an existing one.

``` sh
lbcwallet --create

Do you have an existing wallet seed you want to use? (n/no/y/yes) [no]: no
Your wallet generation seed is: 3d005498ad5e9b7439b857249e328ec34e21845b7d1a7d2a5641d4050c02d0da
```

The created wallet protects the seed with a default passphrase (`"passphrase"`), which can be override with `-p` option:

``` sh
lbcwallet --create -p my-passphrase
```

Start wallet server, and connect it to a lbcd instance.

``` sh
lbcwallet --rpcuser=rpcuser --rpcpass=rpcpass # --rpcconnect=localhost:9245
```

At startup, the wallet will try to unlock itself with the default passphrase (`passphrase`) or an user provided one (using `-p` option).

If the passphrase does not match, the wallet remains locked. User can lock/unlock the wallet using `walletlock` and `walletpassphrase` RPCs.

``` sh
lbcwallet --rpcuser=rpcuser --rpcpass=rpcpass -p my_passphrase
```

## Contributing

Contributions to this project are welcome, encouraged, and compensated.
The [integrated github issue tracker](https://github.com/lbryio/lbcwallet/issues)
is used for this project. All pull requests will be considered.

<!-- ## Release Verification
Please see our [documentation on the current build/verification
process](https://github.com/lbryio/lbcwallet/tree/master/release) for all our
releases for information on how to verify the integrity of published releases
using our reproducible build system.
-->

## License

lbcwallet is licensed under the liberal ISC License.
