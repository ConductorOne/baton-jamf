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

Yes — account creation and deletion only. The connector does **not** implement Grant/Revoke for any resource; Group, User Group, Role, and Site memberships are synced for visibility (access reviews) but cannot be changed through the connector.

| Resource | Grant | Revoke | Create | Delete |
|----------|-------|--------|--------|--------|
| **User** | - | - | ✅ Creates a Jamf directory user (`POST /JSSResource/users/id/0`) | ✅ Deletes a Jamf directory user |
| **User Account** | - | - | ✅ Creates a Jamf Pro console admin account (`POST /JSSResource/accounts/userid/0`), with a C1-generated random password returned as plaintext | ✅ Deletes a Jamf Pro console admin account |
| **Group / User Group / Role / Site** | - | - | - | - |

**Important:** Jamf has two distinct, unrelated account types that both map to the `user` trait — directory Users and console admin User Accounts. The Jamf Pro platform (and this connector) only supports creating **one** of the two types per connector instance, controlled by the `create-account-resource-type` config field (`user` default, or `userAccount`). Deletion is **not** gated by this setting — both types can always be deleted regardless of which one is configured for creation.

Both resource types are advertised in `baton_capabilities.json` as account-provisioning-capable (since both implement the required SDK interfaces), even though only one is actually enabled at runtime per the config above. Attempting to create the non-configured type returns a `codes.Unimplemented` error naming the required config value. This is a known limitation shared with other ConductorOne connectors that expose more than one provisionable account type per connector instance (e.g. baton-aws with IAM users vs. Identity Center users) — it stems from the Baton SDK only supporting a single `AccountCreationSchema` per connector, not per resource type.

## Connector Credentials

### 1. What credentials or information are needed to set up the connector?

| Credential | Required | Description |
|------------|----------|-------------|
| **Username** | Yes | Username of a Jamf Pro user (or service account) with sufficient privileges. |
| **Password** | Yes | Password for the above username. Used once to mint a short-lived Bearer token (`POST /api/v1/auth/token`); the connector refreshes the token itself and does not store the password beyond the process lifetime. |
| **Instance URL** | Yes | Base URL of the Jamf Pro instance (e.g. `https://your-org.jamfcloud.com`). |
| **Account Provisioning Target** | No | `user` (default) or `userAccount` — which account type `CreateAccount` is allowed to create. See the provisioning note above. |

### 2. How are these credentials obtained?

Create (or designate) a Jamf Pro user account with the **Administrator** privilege set and **Full Access** access level. See [Creating a Jamf Pro User Account](https://learn.jamf.com/bundle/jamf-pro-documentation-current/page/Jamf_Pro_User_Accounts_and_Groups.html#ariaid-title3). No API key or OAuth app is needed — the connector authenticates with plain username/password against the Jamf Pro token endpoint.

## Additional Notes

### Jamf Plan Requirements

None identified — the Classic API endpoints this connector uses (`/JSSResource/*`) and the `/api/v1/auth/*` token endpoints are part of standard Jamf Pro, not gated behind a separate add-on or tier.

### Classic API content-type contract

The Jamf Pro Classic API only accepts **XML** for POST/PUT request bodies — JSON is supported for GET responses only. This is easy to get wrong (the SDK's default HTTP helper sends JSON); the client explicitly uses `uhttp.WithXMLBody` for `CreateUser`/`CreateUserAccount`. See https://developer.jamf.com/jamf-pro/docs/getting-started-2.

### API Documentation Links

- [Jamf Pro Classic API overview](https://developer.jamf.com/jamf-pro/docs/getting-started-2)
- [Create User by ID](https://developer.jamf.com/jamf-pro/reference/createuserbyid)
- [Create Account by ID](https://developer.jamf.com/jamf-pro/reference/createaccountbyid)
