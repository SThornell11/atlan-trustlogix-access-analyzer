# TrustLogix Data Access Governance — Atlan App

A custom Atlan Application that scans **Snowflake** and **Databricks** accounts via **TrustLogix**, syncs risk and governance metadata into **Atlan**, and produces a standalone HTML report showing access entitlements and security risks across your data estate.

[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/SThornell11/atlan-trustlogix-access-analyzer)

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture & Data Flow](#architecture--data-flow)
3. [TrustLogix Scanning](#trustlogix-scanning)
4. [Atlan Mapping & Domain Resolution](#atlan-mapping--domain-resolution)
5. [Risk Fetching & Severity Mapping](#risk-fetching--severity-mapping)
6. [What Gets Written to Atlan](#what-gets-written-to-atlan)
7. [Badge Thresholds & Colour Logic](#badge-thresholds--colour-logic)
8. [Tag Management](#tag-management)
9. [Announcement Banner Logic](#announcement-banner-logic)
10. [Persona Metadata Policy](#persona-metadata-policy)
11. [HTML Report](#html-report)
12. [Configuration Reference](#configuration-reference)
13. [Setup & Deployment](#setup--deployment)
14. [Local Testing](#local-testing)
15. [Resilience & Error Handling](#resilience--error-handling)

---

## Overview

On each run the app:

1. **Authenticates** to TrustLogix and fetches all active Snowflake/Databricks accounts.
2. **Scans** each account — databases → schemas → tables — collecting entitlements (who has access to what).
3. **Fetches security alerts** for each account from TrustLogix.
4. **Maps** each TrustLogix database to its Atlan counterpart using database name matching.
5. **Resolves Atlan domains** from the `domainGUIDs` attribute on matched assets.
6. **Groups** accounts under their resolved Atlan domain (or "Unassigned" if no match).
7. **Writes governance metadata** (Custom Metadata, Tags, Announcement banners) to all matched Atlan assets and their parent domain.
8. **Generates an HTML report** at `/tmp/trustlogix_report.html`.

---

## Architecture & Data Flow

```
TrustLogix                          Atlan
──────────                          ─────
Accounts (Snowflake/Databricks)
  └─ Databases
       └─ Schemas                   ←── matched by DATABASE NAME (uppercase)
            └─ Tables
  └─ Alerts (security risks)        ───► Custom Metadata on each matched asset
                                    ───► Tags (rollup + per-category)
                                    ───► Announcement banners
                                    ───► Domain-level rollup BM

HTML Report (/tmp/trustlogix_report.html)
  └─ Domain groups → Accounts → Data Risks + Access Entitlements tree
```

### Key design decisions

- **Database name is the join key.** TrustLogix database names are uppercased and matched against `databaseName` attributes in Atlan. No connection-level mapping is required.
- **Risk data is never pre-bucketed.** Categories come directly from TrustLogix's `category` field (e.g. `shadow_it`, `regulatory_compliance`) and are formatted dynamically at display time — no hardcoded category list exists in the code.
- **Atlan domain assignment uses `domainGUIDs`.** Each Atlan asset carries a `domainGUIDs` attribute (a list of DataDomain GUIDs). The app resolves these to domain display names and groups TrustLogix accounts by the most common domain found across their matched databases.
- **The app is idempotent.** Every run re-checks and re-writes all metadata. Stale tags from previous scans are removed. BM attributes that already have the correct values are still overwritten (with `isOverwrite=true`) to keep Last Scanned timestamps current.

---

## TrustLogix Scanning

### Authentication

Supports two methods, controlled by the `AUTH_METHOD` environment variable:

| `AUTH_METHOD` | How it works |
|---|---|
| `credentials` (default) | `POST /api/login?userType=TENANT_USER` with `loginId` + `password`. Returns a Bearer token stored for the session. XSRF token refreshed from cookies before POST requests. |
| `bearer` | Reads token directly from `TRUSTLOGIX_API_KEY`. No login call needed. |

### Account Discovery

`GET /api/account?status=Active&pageSize=1000`

Returns all active accounts. Filtered to `snowflake` and `databricks` types only. All 7 accounts (or however many exist) are processed on each run — there is no account-level filter in production.

### Hierarchy Scanning

For each account the app drills down three levels:

```
GET /api/metadata/{account_id}/databases?pageSize=1000
  └─ GET /api/metadata/{account_id}/schemas?databaseNames={db}&pageSize=1000
       └─ GET /api/metadata/{account_id}/tables?schemaNames={schema_fqn}&pageSize=1000
```

For each level, entitlements are fetched:

```
GET /api/account/{account_id}/entitlements?objectType={type}&objectName={fqn}&pageSize=1000
```

`objectType` values: `DATABASE`, `DATABASE_SCHEMA` / `SCHEMA` / `DATA_SCHEMA` (tried in order for schemas), `TABLE`.

Entitlements are normalised from whatever field names the API returns (`roleName`/`userName`/`groupName`/`name`, `grantedPrivileges`/`permissions`/`accessRights`/`privileges`) into a consistent `{name, privileges, entity_type}` structure.

---

## Atlan Mapping & Domain Resolution

### Asset Index

On startup the app queries Atlan for all `Table`, `View`, `MaterialisedView`, `Database`, and `Schema` entities (paginated at 100 per page) requesting these attributes:

- `name`, `databaseName`, `schemaName`, `qualifiedName`, `connectionName`
- `domainGUIDs` — the key field for domain resolution
- `productGUIDs` — fetched for context

This builds a map: **`DATABASE_NAME (uppercase)` → list of `{guid, domain, typeName, name, qualifiedName}`**

A typical index run covers ~1,300+ GUIDs across 20+ database paths.

### Domain Resolution

Each asset's `domainGUIDs` attribute contains a list of DataDomain GUIDs. On startup the app also queries all `DataDomain` entities to build a `GUID → domain name` lookup.

For each matched database, all unique non-"Unassigned" domain names are collected. At the account level the **most common domain** across all matched databases wins. If no Atlan domains match, the account is placed under **"Unassigned"**.

```
Account → matched DBs → domainGUIDs on each Atlan asset
                      → GUID lookup → domain names
                      → most common domain = account's domain group
```

---

## Risk Fetching & Severity Mapping

### API Endpoint

Risks are fetched via:

```
GET /api/alerts?accountId={id}&page_no=1&page_size=100&sort_by=severity&sort_order=DESC
```

> **Important:** `page_no` and `page_size` are mandatory parameters — the endpoint returns HTTP 400 without them.

The response envelope is `{"items": [...], "total": N, "pageNo": 1, "pageSize": 100}`.

### Severity Mapping

TrustLogix returns severity as a **numeric string**. The app maps it to standard labels:

| TrustLogix value | Label | Counted as |
|---|---|---|
| `"1"` | `CRITICAL` | High (critical/high bucket) |
| `"2"` | `HIGH` | High (critical/high bucket) |
| `"3"` | `MEDIUM` | Medium |
| `"4"` | `LOW` | Low |

The `risks_summary.high` field — and the "Critical / High" counter shown in the report — is the **sum of CRITICAL + HIGH severity** alerts. Medium and Low are counted separately.

### Category Mapping

The `category` field from the TrustLogix API response (e.g. `shadow_it`, `regulatory_compliance`, `data_exfiltration`) is formatted for display by:
1. Replacing underscores with spaces
2. Title-casing
3. Preserving known acronyms (`IT` stays uppercased — e.g. `shadow_it` → `Shadow IT`)

Categories seen in the demo environment: `Dark Data`, `Data Exfiltration`, `Overly Granted Access`, `Privacy Compliance`, `Regulatory Compliance`, `Security Misconfigurations`, `Shadow IT`.

### Field Mapping

| Report / BM field | TrustLogix source field |
|---|---|
| `category` | `category` → `policyRefId` → `alertName` (first non-null) |
| `details` | `details` → `summary` → `description` (first non-null) |
| `recommendation` | `policyRemediation` (skips generic "View Details" / "Dismiss" actions) |
| `severity` | `severity` (numeric, mapped via `_SEVERITY_MAP`) |

---

## What Gets Written to Atlan

### Custom Metadata — "TrustLogix Data Access Governance"

Written to every matched Atlan asset (Tables, Views, MaterialisedViews, Databases, Schemas) and to the parent DataDomain entity. Always overwritten (`isOverwrite=true`) on each run.

| Attribute | Type | Visible in Overview | Description |
|---|---|---|---|
| Total Risks | int | ✓ | Total alert count from TrustLogix |
| High Severity | int | ✓ | Count of CRITICAL + HIGH alerts |
| Medium Severity | int | | Count of MEDIUM alerts |
| Low Severity | int | | Count of LOW alerts |
| Risk Categories | string | | Comma-separated list of active categories |
| Last Scanned | string | ✓ | UTC timestamp of last run |
| Scan Status | string | ✓ | Human-readable status (see below) |
| Risk Details | textarea | | Per-category breakdown of risk counts |

**Scan Status values:**

| Condition | Scan Status value |
|---|---|
| No risks | `✓ TrustLogix Data Access Governance Verified` |
| Risks but no high/critical | `{total} Risk(s) Found` |
| High/critical risks present | `⚠ {high} High \| {medium} Med \| {low} Low` |

### BM Logo

The Custom Metadata definition uses `logoType: image` + `logoUrl` pointing to the TrustLogix CDN favicon. This is distinct from tag logos and renders reliably in all Atlan UI contexts (overview panel, badges, sidebar) without requiring a browser session cookie.

---

## Badge Thresholds & Colour Logic

Three badges are created/updated on each run, each backed by a Custom Metadata attribute:

### Scan Status badge

| Condition | Colour |
|---|---|
| Equals `✓ TrustLogix Data Access Governance Verified` | Green (`#047960`) |
| Any other value | Red (`#BF1B1B`) |

### High Severity badge

| Condition | Colour |
|---|---|
| `= 0` | Green (`#047960`) |
| `≥ 1` | Red (`#BF1B1B`) |

### Total Risks badge

| Condition | Colour |
|---|---|
| `= 0` | Green (`#047960`) |
| `≥ 1` | Amber (`#F7B43D`) |
| `≥ 5` | Red (`#BF1B1B`) |

Conditions are evaluated top-to-bottom; the first match wins.

---

## Tag Management

Tags in Atlan are **fully dynamic** — the app creates a classification typedef for every unique risk category it encounters, prefixed `TLX_`. Tags are never hardcoded.

### Tag ID generation

```
category_name → strip non-alphanumeric → uppercase → prepend "TLX_"
e.g. "Shadow IT" → "TLX_SHADOW_IT"
```

### Tag colour

| Category name contains | Tag colour |
|---|---|
| `critical`, `exfiltrat`, `breach`, `shadow`, `high` | Red |
| Anything else | Orange |

### Rollup tag — one of three applied per asset

| Risk state | Tag applied |
|---|---|
| Any CRITICAL or HIGH risks | `TrustLogix High Risk` |
| Risks but none high/critical | `TrustLogix Risks Detected` |
| No risks | `TrustLogix Data Access Governance Verified` |

### Per-category tags

When an asset has risks, a tag is also applied for **each distinct category** present in that account's risk data (in addition to the rollup tag).

### Stale tag cleanup

On each run the app reads the current classifications on the asset, identifies any `TLX_` tags that should no longer be there, removes them, then applies the new desired set. Non-TrustLogix tags on the asset are never touched.

### Tag logo

Tags use `iconType: image` + `imageId` (uploaded via `POST /api/service/images`). A `logoUrl` CDN hint is also stored. On demo/local instances where `/api/service/images/{id}` returns 401 (requires browser session cookie), the tag falls back to the 🛡 emoji. In production Atlan, the uploaded image renders correctly for authenticated users.

---

## Announcement Banner Logic

An announcement banner is set at the top of each matched asset's overview page. The banner type changes based on risk severity:

| Condition | Banner type | Title |
|---|---|---|
| High/critical risks | `issue` (red) | `TrustLogix: {N} High Severity Risk(s) Detected` |
| Medium/low risks only | `warning` (yellow) | `TrustLogix: {N} Risk(s) Detected` |
| No risks | `information` (blue) | `TrustLogix: Data Access Governance Verified` |

The banner message always includes the risk breakdown (high/medium/low counts), active categories, and the last scanned timestamp.

---

## Persona Metadata Policy

Atlan hides custom metadata from users by default. To make the **TrustLogix Data Access Governance** section visible in the asset sidebar, the app attempts to create a metadata `AuthPolicy` on every persona:

- **Policy name:** `TrustLogix Data Access Governance - View Custom Metadata`
- **Actions:** `persona-asset-read`, `persona-business-update-metadata`
- **Scope:** All connections (dynamically fetched from Atlan)
- **Deduplication:** Checks for an existing TLX policy on each persona before creating

If the API token lacks persona-admin permissions (HTTP 400 / `ATLAS-400-00-029`), a single consolidated warning is logged at the end with manual instructions:

```
Atlan Admin → Governance → Personas → [persona] → Policies tab
→ Add policy → Metadata policy
→ Name: "TrustLogix Data Access Governance - View"
→ Actions: View
→ Custom metadata: TrustLogix Data Access Governance
→ Assets: All assets → Save
```

To target a specific persona only, set the `ATLAN_PERSONA_NAME` environment variable (case-insensitive match).

---

## HTML Report

Generated at `/tmp/trustlogix_report.html` on every run. Built with Tailwind CSS + Alpine.js (both loaded from CDN), fully self-contained as a single HTML file.

### Structure

- **Left sidebar:** Tree view of Domains → Accounts → (Data Risks | Access Analyzer)
- **Right panel:** Detail view for the selected node

### Node types and what they show

| Node type | Detail panel shows |
|---|---|
| Account | Risk summary (Critical/High count + Total count) |
| Data Risks | All risk cards: category badge, severity pill, details text |
| Database / Schema / Table | Entitlement table: Role/User/Group name + privileges |

### Risk severity display

Each risk card shows the mapped severity label: `CRITICAL`, `HIGH`, `MEDIUM`, or `LOW`. The **"Critical / High"** summary counter on the account header reflects the combined count of both CRITICAL and HIGH alerts.

### Empty states

- **No risks:** Shows a green checkmark with "Data Access Governance Verified"
- **No entitlements at DB/Schema level:** Shows "No direct entitlements at this level — expand to view table-level access below"
- **No entitlements at table level:** Shows "No direct entitlements discovered for this table"

---

## Configuration Reference

All configuration is via environment variables:

| Variable | Required | Description |
|---|---|---|
| `TRUSTLOGIX_BASE_URL` | Yes | TrustLogix instance URL, e.g. `https://demo.trustlogix.io` |
| `TRUSTLOGIX_TENANT_ID` | Yes | Your TrustLogix tenant ID |
| `AUTH_METHOD` | Yes | `credentials` (username/password) or `bearer` (existing token) |
| `CLIENT_ID` | If `AUTH_METHOD=credentials` | TrustLogix username/email |
| `CLIENT_SECRET` | If `AUTH_METHOD=credentials` | TrustLogix password |
| `TRUSTLOGIX_API_KEY` | If `AUTH_METHOD=bearer` | Pre-existing TrustLogix Bearer token |
| `ATLAN_BASE_URL` | Yes | Atlan instance URL, e.g. `https://your-instance.atlan.com` |
| `ATLAN_API_KEY` | Yes | Atlan API token (Bearer) |
| `ATLAN_PERSONA_NAME` | No | Restrict metadata policy to a single named persona. Leave blank to apply to all personas. |

---

## Setup & Deployment

### 1. Prerequisites

- Access to an Atlan instance
- A TrustLogix tenant with Service User credentials
- Docker Desktop installed locally

### 2. Build the Image

```bash
docker build --platform linux/amd64 -t trustlogix-analyzer .
```

### 3. Push to Registry

Follow the [Atlan Partner Guide](https://docs.atlan.com/product/capabilities/build-apps/partner-with-us/how-tos/push-images-to-harbor-registry) to push to Atlan Harbor or your own registry:

```bash
docker tag trustlogix-analyzer <your-registry>/trustlogix-analyzer:latest
docker push <your-registry>/trustlogix-analyzer:latest
```

### 4. Deploy to Atlan

1. Edit `atlan.yml` — update the `image` field to your registry URL.
2. Go to **Atlan Admin Center → Workflows**.
3. Click **Add Custom Workflow** and upload `atlan.yml`.
4. Configure the required parameters in the Atlan UI and run.

---

## Local Testing

Create a `.env` file (gitignored) with your credentials:

```env
TRUSTLOGIX_BASE_URL=https://demo.trustlogix.io
TRUSTLOGIX_TENANT_ID=your_tenant_id
AUTH_METHOD=credentials
CLIENT_ID=user@example.com
CLIENT_SECRET=your_password
ATLAN_BASE_URL=https://your-instance.atlan.com
ATLAN_API_KEY=your_atlan_api_token
```

Run with the report saved locally:

```bash
mkdir -p output
docker run --rm --env-file .env -v $(pwd)/output:/tmp trustlogix-analyzer
# Report saved to output/trustlogix_report.html
```

---

## Resilience & Error Handling

### HTTP retry policy

All Atlan API calls retry up to 3 times with exponential backoff (2s, 5s, 10s) on connection errors and 5xx responses. Rate-limit responses (HTTP 429) respect the `Retry-After` header.

### Fail-fast on 403s

If 3 consecutive HTTP 403 responses are received from Atlan, the sync aborts immediately to avoid flooding the API with permission-denied requests. This typically means the API token lacks the required permissions for Business Metadata write access.

### Atlan not configured

If `ATLAN_BASE_URL` is empty or `ATLAN_API_KEY` is missing, the app runs in **report-only mode** — TrustLogix is still fully scanned and the HTML report is still generated, but no metadata is written to Atlan.

### BM migration

If the Custom Metadata definition was previously named "TrustLogix Governance" (the old name), it is automatically found and renamed to "TrustLogix Data Access Governance" on the next run without creating a duplicate or losing existing attribute values.

### Missing BM attributes

If the existing BM definition is missing any of the 8 expected attributes (e.g. because it was created by an older version of the app), the missing attributes are added automatically with `isOptional=true` before syncing begins.
