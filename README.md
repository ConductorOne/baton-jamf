# baton-jamf

`baton-jamf` is a connector for Jamf built using the [Baton SDK](https://github.com/conductorone/baton-sdk). It communicates with the Jamf API to sync data about users, user accounts, groups, user groups, roles, sites, and managed devices, and can provision Jamf accounts (create/delete) and grant/revoke access to groups, user groups, roles, sites, and managed devices.

Check out [Baton](https://github.com/conductorone/baton) to learn more the project in general.

## Capabilities

| Capability | Status |
|------------|--------|
| Sync | Yes |
| Account Creation (Users, User Accounts) | Yes — one type per connector instance, see `create-account-resource-type` below |
| Account Deletion (Users, User Accounts) | Yes |
| Provisioning (Grant/Revoke) | Yes — Groups (`userAccount` principal only, Group Access accounts only), User Groups (static groups only), Sites (`user` principal only), Managed Devices (`assigned`, `user` principal only, opt-in — see Data Model below), Roles (built-in privilege sets and individual privileges, `userAccount`/`group` principal, see below). |

Account creation/deletion and Grant/Revoke all require `-p`/`$BATON_PROVISIONING` to be set; without it the connector only syncs.

Tested with Jamf Pro 11.32.1. Managed Devices use the Jamf Pro API v4 computers-inventory and v2 mobile-devices endpoints.

## Required Jamf privileges

The Administrator privilege set covers everything. For least privilege, grant:

| Task | Privilege |
|---|---|
| Startup, config validation, token refresh | None — any enabled local Jamf Pro account (every `Custom` set also keeps `Read License Information`) |
| Sync users | `Read User` |
| Sync user accounts and groups | `Read Accounts` |
| Sync user groups | `Read Static User Groups`, `Read Smart User Groups` (Smart is only needed when smart groups exist — it's checked per group) |
| Sync sites | `Read Sites`, `Read User`, `Read Static User Groups`, `Read Smart User Groups`, `Read Accounts` (site grants are built by reading users, user groups and accounts) |
| Sync roles | `Read API Roles`, `Read Accounts` |
| Sync managed devices (opt-in) | `Read Computers`, `Read Mobile Devices`, `Read User` (needed even if `user` isn't synced) |
| Create/delete users | `Create User` and `Read User` (the connector reads the user back after creating); `Delete User` |
| Create/delete user accounts | `Create Accounts` and `Read Accounts`; `Delete Accounts` |
| Group Grant/Revoke (`userAccount` principal) | `Read Accounts`, `Update Accounts` |
| Role Grant/Revoke (`userAccount`/`group` principal) | `Read Accounts`, `Update Accounts` (`Read API Roles` is not needed for writes) |
| User Group Grant/Revoke (static group) | `Read Static User Groups`, `Update Static User Groups` |
| Site Grant/Revoke (`user` principal) | `Read User`, `Update User` |
| Managed Device Grant/Revoke | Computers: `Read Computers`, `Update Computers`, `Read User`. Mobile devices: `Read Mobile Devices`, `Update Mobile Devices`, `Read User`, plus `Assign Users to Mobile Devices` to Grant (clearing the assignee on Revoke doesn't need it) |

`Read Accounts`/`Create Accounts`/`Update Accounts`/`Delete Accounts` cover both admin user accounts and admin groups — Jamf has no separate privilege for account groups. Every write path reads the object first, so each `Update` privilege above needs its `Read` counterpart too.

Jamf reports a denied write differently depending on which API it uses. The Classic API (`/JSSResource` — Users, Accounts, Static User Groups) answers a missing privilege with HTTP 401, indistinguishable from an invalid or expired token. The Jamf Pro API (`/api/v1`, `/api/v2`, `/api/v4` — the roles catalog, Computers, Mobile Devices) answers with HTTP 403, reported as a permission error.

Group Grant/Revoke adds or removes a `userAccount` from an admin account
group's member list. A group with no members cannot receive its first member
through the connector, and Revoke on such a group returns a retryable error
instead of reporting success — Jamf can transiently return an empty member
list even when the group genuinely has members, and the connector refuses to
write over (or assume someone was removed from) a list it can't trust is
complete. Only Group Access
accounts can usefully be granted membership — a Full or Site Access account's
rights come from its own `privilege_set`, not its groups, so Grant rejects
adding one (membership grants it nothing). Do not use Grant/Revoke on
directory (LDAP) groups: their membership is managed by the directory and the
connector does not detect them.

Smart User Groups cannot be granted/revoked (membership is computed from
criteria, not assignable) — the connector rejects these before calling the
Jamf API. Site Grant/Revoke is only provisionable for the `user` principal;
`userGroup`/`userAccount`/`group` site membership remains sync-only (single-
valued/exclusive, not a true membership list). Managed Device `assigned` is
single-valued — granting it to a new user displaces whichever user was
previously assigned. Grant currently only works on devices that already have
an assigned user (the `assigned` entitlement is only emitted for devices that
report an assignee) — it cannot be used to assign a previously-unassigned
device to a user. Computers use the Jamf Pro v4 computers-inventory API.
Granting a computer overwrites the assignee's username, name, email,
position and phone with the new user's values (Jamf never fills these in on
its own for computers); Revoke clears all five. Mobile devices only ever
have their username set directly — Jamf derives the assignee's name, email
and phone from the directory automatically, and Revoke clears all of them
together by clearing the username.

Role Grant/Revoke sets or clears a `userAccount` or `group`'s role. All three
built-in privilege sets (`Administrator`, `Auditor`, `Enrollment Only`) and
every individual privilege are grantable — `Custom` itself is not a role you
grant directly. Granting a set displaces whichever one the principal
previously held. Revoke moves the principal to `Custom` with only the
`Read License Information` privilege — the lowest access Jamf allows, since
`privilege_set` has no neutral "no access" value. Jamf keeps that privilege on
every `Custom` set it creates and never lets a client remove it, so revoking
it specifically is rejected. Individual privileges can
only be granted while the principal's `privilege_set` is already `Custom`:
the flow is Revoke the current set first (which moves it to Custom), then
Grant the individual privileges — granting a built-in set again later leaves
Custom and discards those individual privileges. Group Access accounts are
not supported for Role Grant/Revoke — their rights come from their groups, so
assign the role to the group instead. Changing a Full or Site Access
account's role removes it from any admin group it belonged to (that
membership granted it nothing). A write rejected by the connector's own Jamf
account shows up as a 401 authentication error from Jamf.

## Jamf Pro console admin account creation (`userAccount`)

When `--create-account-resource-type=userAccount`, a created account is
`Enabled` with `Full Access`, and its `privilege_set` profile field controls
its access level: `Administrator`, `Auditor` (the default), `Enrollment Only`,
or `Custom`. A random password is generated and returned once, as plaintext,
in the provisioning response — the connector does not store it.

For `Custom`, set at least one of the following profile fields to a list of
Jamf privilege names for that category — the connector rejects the request
otherwise, since a `Custom` account with no privileges at all would have no
access:

- `privileges_jss_objects`
- `privileges_jss_settings`
- `privileges_jss_actions`
- `privileges_recon`
- `privileges_casper_admin`
- `privileges_casper_remote`
- `privileges_casper_imaging`

Conversely, setting any of these fields when `privilege_set` is not `Custom`
is also rejected — they only apply to `Custom` accounts.

Privilege names are validated server-side by Jamf, not by this connector — an
invalid name returns a Jamf API error rather than a local validation error.

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
docker run --rm -v $(pwd):/out -e BATON_USERNAME=jamfUsername -e BATON_PASSWORD=jamfPassword -e BATON_INSTANCE_URL=https://jamfProServerUrl.example.com public.ecr.aws/conductorone/baton-jamf:latest -f "/out/sync.c1z"
docker run --rm -v $(pwd):/out ghcr.io/conductorone/baton:latest -f "/out/sync.c1z" resources
```

## source

```
go install github.com/conductorone/baton/cmd/baton@main
go install github.com/conductorone/baton-jamf/cmd/baton-jamf@main

BATON_USERNAME=jamfUsername BATON_PASSWORD=jamfPassword BATON_INSTANCE_URL=https://jamfProServerUrl.example.com baton-jamf
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
- Managed Devices — opt-in, off by default. Enable it by passing `managedDevice`
  in `--sync-resource-types`/`$BATON_SYNC_RESOURCE_TYPES` alongside the other
  resource type IDs you want to keep syncing (e.g.
  `user,userAccount,group,userGroup,role,site,managedDevice`) — passing this
  flag replaces the default set rather than adding to it, and listing only
  `managedDevice` syncs nothing else. Provisioning for devices is only
  available when `managedDevice` is included in the sync.

Account creation/deletion and Grant/Revoke (see Capabilities above) all
require `-p`/`$BATON_PROVISIONING`.

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
      --instance-url string                 required: Base URL of your Jamf Pro instance, including https:// (for example https://yourcompany.jamfcloud.com) ($BATON_INSTANCE_URL)
      --log-format string                   The output format for logs: json, console ($BATON_LOG_FORMAT) (default "json")
      --log-level string                    The log level: debug, info, warn, error ($BATON_LOG_LEVEL) (default "info")
      --password string                     required: Password for your Jamf Pro instance ($BATON_PASSWORD)
  -p, --provisioning                        This must be set in order for provisioning actions to be enabled ($BATON_PROVISIONING)
      --skip-entitlements-and-grants         This must be set to skip syncing of entitlements and grants ($BATON_SKIP_ENTITLEMENTS_AND_GRANTS)
      --skip-full-sync                      This must be set to skip a full sync ($BATON_SKIP_FULL_SYNC)
      --sync-resource-types strings         The resource type IDs to sync ($BATON_SYNC_RESOURCE_TYPES)
      --sync-resources strings              The resource IDs to sync ($BATON_SYNC_RESOURCES)
      --ticketing                           This must be set to enable ticketing support ($BATON_TICKETING)
      --username string                     required: Username for your Jamf Pro instance ($BATON_USERNAME)
  -v, --version                             version for baton-jamf

Use "baton-jamf [command] --help" for more information about a command.
```

See `--help` for the full, up-to-date list of flags (this trims flags shared by every Baton connector that are rarely needed, e.g. OpenTelemetry and worker-tuning options).
