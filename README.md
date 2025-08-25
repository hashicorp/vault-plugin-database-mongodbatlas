# HashiCorp Vault Database Secrets Engine - MongoDB Atlas plugin

MongoDB Atlas is one of the supported plugins for the HashiCorp Vault Database Secrets Engine and allows for the programmatic generation of unique, ephemeral MongoDB [Database User](https://docs.atlas.mongodb.com/reference/api/database-users/) credentials in MongoDB Atlas Projects.

**The plugin is included from version 1.4 of Vault.**

**Please note:** If you would like to install a different version of this plugin than the one that is bundled with Vault, versions v0.2.0 onwards of this plugin are incompatible with Vault versions before 1.6.0 due to an update of the database plugin interface.

## Support, Bugs and Feature Requests

Support for the HashiCorp Vault Database Secrets Engine - MongoDB Atlas is provided under MongoDB Atlas support plans. Please submit support questions within the Atlas UI.  Vault support is via HashiCorp.

Bugs should be filed under the Issues section of this repo.

Feature requests can be submitted in the Issues section or [directly to MongoDB](https://feedback.mongodb.com/forums/924145-atlas) - just select the Vault plugin as the category or vote for an already suggested feature.

## Quick Links

- [Database Secrets Engine for MongoDB Atlas - Docs](https://developer.hashicorp.com/vault/docs/secrets/databases/mongodbatlas)
- [Database Secrets Engine for MongoDB Atlas - API Docs](https://developer.hashicorp.com/vault/api-docs/secret/databases/mongodbatlas)
- [MongoDB Atlas Website](https://www.mongodb.com/cloud/atlas)
- [Vault Website](https://www.vaultproject.io)

**Please note**: HashiCorp takes Vault's security and their users' trust very seriously, as does MongoDB.

If you believe you have found a security issue in Vault or with this plugin, _please responsibly disclose_ by
contacting HashiCorp at [security@hashicorp.com](mailto:security@hashicorp.com) and contact MongoDB
directly via [security@mongodb.com](mailto:security@mongodb.com) or
[open a ticket](https://jira.mongodb.org/plugins/servlet/samlsso?redirectTo=%2Fbrowse%2FSECURITY) (link is external).

## Acceptance Testing

In order to perform acceptance testing, you need to provide all of the necessary information to
connect to a MongoDB Atlas Project. All `ATLAS_*` environment variables must be
provided in order for the acceptance tests to run properly. A cluster must be
available during the test. A
[free tier cluster](https://docs.atlas.mongodb.com/tutorial/deploy-free-tier-cluster/)
can be provisioned manually to test.

| Environment variable | Description                                                      |
|----------------------|------------------------------------------------------------------|
| ATLAS_PUBLIC_KEY     | The Atlas API public key                                         |
| ATLAS_PRIVATE_KEY    | The Atlas API private key                                        |
| ATLAS_PROJECT_ID     | The desired project ID or group ID                               |
| ATLAS_CLUSTER_NAME   | The desired cluster's name, e.g., vault-project.xyz.mongodb.net  |
| ATLAS_ALLOWLIST_IP   | The public IP of the machine that the test is being performed    |

Then you can run `make testacc` to execute the tests.

## Updating the Changelog

All pull requests that introduce a user-facing change must include a changelog
entry. We use the [changie](https://changie.dev/) tool to manage these entries
and automate the release process.

---
### 1. Installing Changie

You only need to do this once. If you don't have `changie` installed, choose one of the options below.

* **Homebrew** (macOS):
    ```shell
    brew install changie
    ```
* **Go Install**:
    ```shell
    go install github.com/miniscruff/changie@latest
    ```
* **Other Methods**:
  See the [official changie installation guide](https://changie.dev/guide/installation/) for other options, including pre-compiled binaries.

---
### 2. Creating an Entry

Once your code changes are complete, create the changelog entry:

1.  **Run the command** in your terminal:
    ```shell
    changie new
    ```
2.  **Follow the prompts.** An interactive prompt will ask you to select the
    kind of change (e.g., `BREAKING CHANGES`, `NOTES`, `FEATURES`) and write a concise description of
    what you changed.

3.  **Commit the new file.** After you're done, `changie` will create a new
    YAML file in the `.changie/unreleased` directory. Commit this file along with your other
    code changes before submitting your pull request.
