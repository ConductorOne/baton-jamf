# baton-jamf

`baton-jamf` is a connector for Jamf built using the [Baton SDK](https://github.com/conductorone/baton-sdk). It communicates with the Jamf API to sync data about users, groups and roles.

Check out [Baton](https://github.com/conductorone/baton) to learn more the project in general.

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
  completion         Generate the autocompletion script for the specified shell
  help               Help about any command

Flags:
      --client-id string              The client ID used to authenticate with ConductorOne ($BATON_CLIENT_ID)
      --client-secret string          The client secret used to authenticate with ConductorOne ($BATON_CLIENT_SECRET)
  -f, --file string                   The path to the c1z file to sync with ($BATON_FILE) (default "sync.c1z")
  -h, --help                          help for baton-jamf
      --instance-url string           URL of your Jamf Pro instance. ($BATON_INSTANCE_URL)
      --log-format string             The output format for logs: json, console ($BATON_LOG_FORMAT) (default "json")
      --log-level string              The log level: debug, info, warn, error ($BATON_LOG_LEVEL) (default "info")
      --password string               Password for your Jamf Pro instance. ($BATON_PASSWORD)
      --username string               Username for your Jamf Pro instance. ($BATON_USERNAME)
  -v, --version                       version for baton-jamf

Use "baton-jamf [command] --help" for more information about a command.

```
