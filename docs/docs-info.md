# Baton Jamf - Connector Documentation

This document provides information needed to set up and use the connector.

## Connector Capabilities

### 1. What resources does the connector sync?

| Resource | Description |
|----------|-------------|
| **User** | Jamf Pro directory user — metadata about an end user, not a console login. |
| **User Account** | Jamf Pro console admin account — can log in to the Jamf Pro web console. |
| **Group** | Admin account group (site-scoped access level + privilege set), with membership. |
| **User Group** | Directory user group (static or smart), with membership. |
| **Role** | Static privilege sets (Administrator, Auditor, Enrollment Only) plus custom privileges surfaced via the Jamf API privileges endpoint. Membership reflects which groups/accounts hold each privilege. |
| **Site** | Jamf Pro site. Membership reflects which users, user groups, accounts, and groups are scoped to that site. |
| **Managed Device** | Computers and mobile devices from Jamf Pro inventory. **Opt-in** — off by default, must be explicitly selected via `--sync-resource-types managedDevice`. Requires the **Read Computers** and **Read Mobile Devices** Jamf API privileges when enabled. |

### 2. Can the connector provision any resources? If so, which ones?

Yes — account creation/deletion for **User** and **User Account**, plus Grant/Revoke for **Group** (`userAccount` principal, Group Access accounts only), **User Group** (static groups only), **Site** (`user` principal only), **Role** (`userAccount`/`group` principal), and **Managed Device** (`assigned` entitlement, `user` principal, opt-in). All provisioning requires `-p`/`$BATON_PROVISIONING`; without it the connector only syncs.

| Resource | Grant | Revoke | Create | Delete |
|----------|-------|--------|--------|--------|
| **User** | - | - | ✅ Creates a Jamf directory user (`POST /JSSResource/users/id/0`) | ✅ Deletes a Jamf directory user |
| **User Account** | - | - | ✅ Creates a Jamf Pro console admin account (`POST /JSSResource/accounts/userid/0`), with a C1-generated random password returned as plaintext | ✅ Deletes a Jamf Pro console admin account |
| **Group** | ✅ `userAccount`, Group Access only | ✅ | - | - |
| **User Group** | ✅ `user`, static groups only | ✅ | - | - |
| **Role** | ✅ `userAccount`/`group` | ✅ | - | - |
| **Site** | ✅ `user` only | ✅ | - | - |
| **Managed Device** | ✅ `user` (`assigned`), opt-in | ✅ | - | - |

**Important:** Jamf has two distinct, unrelated account types that both map to the `user` trait — directory Users and console admin User Accounts. The Jamf Pro platform (and this connector) only supports creating **one** of the two types per connector instance, controlled by the `create-account-resource-type` config field (`user` default, or `userAccount`). Deletion is **not** gated by this setting — both types can always be deleted regardless of which one is configured for creation.

Only the configured target advertises account creation; Delete works for both types.

### 3. Managed Devices is opt-in

Managed Devices is off by default so existing connectors keep working after upgrading. Self-hosted, set `BATON_SYNC_RESOURCE_TYPES` (or `--sync-resource-types`) to `user,userAccount,group,userGroup,role,site,managedDevice` to sync everything including devices — this flag replaces the default sync set rather than adding to it, so listing only `managedDevice` syncs nothing else. Provisioning for devices is only available when `managedDevice` is included in the sync.

## Connector Credentials

### 1. What credentials or information are needed to set up the connector?

| Credential | Required | Description |
|------------|----------|-------------|
| **Username** | Yes | Username of a Jamf Pro user (or service account) with sufficient privileges. |
| **Password** | Yes | Password for the above username. Exchanged for a short-lived Bearer token (`POST /api/v1/auth/token`); the connector keeps the username and password in memory for the life of the process to re-authenticate (keep-alive, or a fresh login) whenever the token expires. |
| **Instance URL** | Yes | Base URL of the Jamf Pro instance (e.g. `https://your-org.jamfcloud.com`). |
| **Account Provisioning Target** | No | `user` (default) or `userAccount` — which account type `CreateAccount` is allowed to create. See the provisioning note above. |

### 2. How are these credentials obtained?

Create (or designate) a Jamf Pro user account with the **Administrator** privilege set and **Full Access** access level. See [Creating a Jamf Pro User Account](https://learn.jamf.com/bundle/jamf-pro-documentation-current/page/Jamf_Pro_User_Accounts_and_Groups.html#ariaid-title3). No API key or OAuth app is needed — the connector authenticates with plain username/password against the Jamf Pro token endpoint.

### 3. Authentication

The connector signs in as a local Jamf Pro user account, not a Jamf API client (client ID/secret) — API clients are not supported. A local account can still authenticate to the API even when SSO is enabled for the Jamf Pro server.

See the "Jamf account privileges" section of the README / connector docs page for the least-privilege Jamf privileges required per capability.

## Additional Notes

### Jamf Plan Requirements

None identified — every endpoint below is part of standard Jamf Pro, not gated behind a separate add-on or tier. The connector uses both the Classic API (`/JSSResource/*`) and the Jamf Pro API (`/api/*`):

- Classic API: `/JSSResource/users`, `/JSSResource/accounts`, `/JSSResource/usergroups`, `/JSSResource/sites` (and their `/id/{id}` and create/update/delete variants) — see the links below.
- Jamf Pro API: `POST /api/v1/auth/token` and `POST /api/v1/auth/keep-alive` (authentication), `GET /api/v1/api-role-privileges` (Role sync), `GET /api/v4/computers-inventory` and `PATCH /api/v4/computers-inventory-detail/{id}` (Managed Device computers), `GET`/`PATCH /api/v2/mobile-devices[/{id}]` (Managed Device mobile devices).

### Classic API content-type contract

The Jamf Pro Classic API only accepts **XML** for POST/PUT request bodies — JSON is supported for GET responses only. This is easy to get wrong (the SDK's default HTTP helper sends JSON); the client explicitly uses `uhttp.WithXMLBody` for `CreateUser`/`CreateUserAccount`. See https://developer.jamf.com/jamf-pro/docs/getting-started-2.

### API Documentation Links

- [Jamf Pro Classic API overview](https://developer.jamf.com/jamf-pro/docs/getting-started-2)
- [Create User by ID](https://developer.jamf.com/jamf-pro/reference/createuserbyid)
- [Create Account by ID](https://developer.jamf.com/jamf-pro/reference/createaccountbyid)
- [Create bearer token](https://developer.jamf.com/jamf-pro/reference/post_v1-auth-token)
- [Refresh token (keep-alive)](https://developer.jamf.com/jamf-pro/reference/post_v1-auth-keep-alive)
- [API role privileges catalog](https://developer.jamf.com/jamf-pro/reference/get_v1-api-role-privileges)
- [Computers inventory (v4)](https://developer.jamf.com/jamf-pro/reference/get_v4-computers-inventory)
- [Computers inventory detail PATCH (v4)](https://developer.jamf.com/jamf-pro/reference/patch_v4-computers-inventory-detail-id)
- [Mobile devices (v2)](https://developer.jamf.com/jamf-pro/reference/get_v2-mobile-devices)
- [Mobile device PATCH (v2)](https://developer.jamf.com/jamf-pro/reference/patch_v2-mobile-devices-id)
