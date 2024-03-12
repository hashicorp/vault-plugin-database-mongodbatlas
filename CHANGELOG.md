## Unreleased

IMPROVEMENTS:
* Updated dependencies:
  * `github.com/hashicorp/vault/sdk` v0.10.2 -> v0.11.0
  * `go.mongodb.org/mongo-driver` v1.13.1 -> v1.14.0

## v0.11.0

CHANGES:
* Building with go 1.21.7

IMPROVEMENTS:
* Updated dependencies:
  * `github.com/hashicorp/go-hclog` v1.5.0 -> v1.6.2
  * `github.com/hashicorp/vault/sdk` v0.9.2 -> v0.10.2
  * `go.mongodb.org/atlas` v0.33.0 -> v0.36.0
  * `go.mongodb.org/mongo-driver` v1.12.1 -> v1.13.1
  * `golang.org/x/net` v0.8.0 -> v0.17.0
  * `google.golang.org/grpc` v1.53.0 -> 1.57.1
  * `golang.org/x/crypto` v0.6.0 -> v0.17.0
  * `github.com/docker/docker` v24.0.5 -> v24.0.7

## v0.10.1

IMPROVEMENTS:
* Updated dependencies:
   * `github.com/hashicorp/vault/sdk` v0.9.2-0.20230530190758-08ee474850e0 -> v0.9.2
   * `github.com/mongodb-forks/digest` v1.0.4 -> v1.0.5
   * `go.mongodb.org/atlas` v0.28.0 -> v0.33.0
   * `go.mongodb.org/mongo-driver` v1.11.6 -> v1.12.1

## v0.10.0

CHANGES:

- Dependency upgrades
- Add support for X509 client certificate credentials [[GH-57]](https://github.com/hashicorp/vault-plugin-database-mongodbatlas/pull/57)

## v0.9.0

CHANGES:

- Replace usage of useragent.String with useragent.PluginString [[GH-42]](https://github.com/hashicorp/vault-plugin-database-mongodbatlas/pull/42)
