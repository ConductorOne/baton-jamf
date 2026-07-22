# baton-jamf

`baton-jamf` is a connector for Jamf built using the [Baton SDK](https://github.com/conductorone/baton-sdk). It communicates with the Jamf API to sync data about users, user accounts, groups, user groups, roles, sites, and managed devices, and can provision (create/delete) Jamf accounts.

Check out [Baton](https://github.com/conductorone/baton) to learn more the project in general.

## Capabilities

| Capability | Status |
|------------|--------|
| Sync | Yes |
| Account Creation (Users, User Accounts) | Yes — one type per connector instance, see `create-account-resource-type` below |
| Account Deletion (Users, User Accounts) | Yes |
| Provisioning (Grant/Revoke) | No — Groups, User Groups, Roles, and Sites are synced for visibility only |

# Getting Started

## Prerequisites

1. Jamf Pro instance

## brew

```
brew install conductorone/baton/baton conductorone/baton/baton-jamf
baton-jamf
baton resources
```

## docker

```
docker run --rm -v $(pwd):/out -e BATON_USERNAME=jamfUsername BATON_PASSWORD=jamfPassword BATON_INSTANCE_URL=https://jamfProServerUrl.example.com ghcr.io/conductorone/baton-jamf:latest -f "/out/sync.c1z"
docker run --rm -v $(pwd):/out ghcr.io/conductorone/baton:latest -f "/out/sync.c1z" resources
```

## source

```
go install github.com/conductorone/baton/cmd/baton@main
go install github.com/conductorone/baton-jamf/cmd/baton-jamf@main

BATON_USERNAME=jamfUsername BATON_PASSWORD=jamfPassword BATON_INSTANCE_URL=https://jamfProServerUrl.example.com
baton resources
```

# Data Model

`baton-jamf` pulls down information about the following Jamf resources:
- Users
- Groups
- User Accounts
- User Groups
- Roles
- Sites
- Managed Devices

# Contributing, Support, and Issues

We started Baton because we were tired of taking screenshots and manually building spreadsheets. We welcome contributions, and ideas, no matter how small -- our goal is to make identity and permissions sprawl less painful for everyone. If you have questions, problems, or ideas: Please open a Github Issue!

See [CONTRIBUTING.md](https://github.com/ConductorOne/baton/blob/main/CONTRIBUTING.md) for more details.

# `baton-jamf` Command Line Usage

```
baton-jamf

Usage:
  baton-jamf [flags]
  baton-jamf [command]

Available Commands:
  capabilities       Get connector capabilities
  completion         Generate the autocompletion script for the specified shell
  config             Get the connector config schema
  health-check       Check the health of a running connector
  help               Help about any command

Flags:
      --client-id string                    The client ID used to authenticate with ConductorOne ($BATON_CLIENT_ID)
      --client-secret string                The client secret used to authenticate with ConductorOne ($BATON_CLIENT_SECRET)
      --create-account-resource-type string Which Jamf account type C1 should create when provisioning accounts. 'user' (default) creates directory users; 'userAccount' creates Jamf Pro console admin accounts. Only one type can be created at a time per connector instance. ($BATON_CREATE_ACCOUNT_RESOURCE_TYPE) (default "user")
  -f, --file string                         The path to the c1z file to sync with ($BATON_FILE) (default "sync.c1z")
  -h, --help                                help for baton-jamf
      --instance-url string                 required: URL of your Jamf Pro instance ($BATON_INSTANCE_URL)
      --log-format string                   The output format for logs: json, console ($BATON_LOG_FORMAT) (default "json")
      --log-level string                    The log level: debug, info, warn, error ($BATON_LOG_LEVEL) (default "info")
      --password string                     required: Password for your Jamf Pro instance ($BATON_PASSWORD)
  -p, --provisioning                        This must be set in order for provisioning actions to be enabled ($BATON_PROVISIONING)
      --skip-full-sync                      This must be set to skip a full sync ($BATON_SKIP_FULL_SYNC)
      --sync-resource-types strings         The resource type IDs to sync ($BATON_SYNC_RESOURCE_TYPES)
      --ticketing                           This must be set to enable ticketing support ($BATON_TICKETING)
      --username string                     required: Username for your Jamf Pro instance ($BATON_USERNAME)
  -v, --version                             version for baton-jamf

Use "baton-jamf [command] --help" for more information about a command.
```

See `--help` for the full, up-to-date list of flags (this trims flags shared by every Baton connector that are rarely needed, e.g. OpenTelemetry and worker-tuning options).
