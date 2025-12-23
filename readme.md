A custom Atlan Application that scans **Snowflake** and **Databricks** accounts via **TrustLogix**, maps them to **Atlan Data Products**, and visualizing access entitlements in a unified dashboard.

## Features
- **Multi-Source Discovery:** Automatically finds active Snowflake and Databricks accounts in TrustLogix.
- **Atlan Integration:** Maps discovered tables to their corresponding Data Products and Domains in Atlan.
- **Deep Access Analysis:** Drills down from Domain -> Account -> Database -> Schema -> Table to show exactly which Users, Roles, and Groups have access.
- **Secure:** Uses Atlan's native secret management for credentials.

## Setup & Deployment

### 1. Prerequisites
- access to an Atlan instance.
- A TrustLogix Tenant ID and Service User credentials.
- Docker Desktop installed locally.

### 2. Build the Image
```bash
docker build --platform linux/amd64 -t trustlogix-analyzer .
```

### 3. Push to Registry (Atlan Harbor or GHCR)
Follow the [Atlan Partner Guide](https://docs.atlan.com/product/capabilities/build-apps/partner-with-us/how-tos/push-images-to-harbor-registry) to push your image.
```bash
docker tag trustlogix-analyzer <your-registry>/trustlogix-analyzer:v1
docker push <your-registry>/trustlogix-analyzer:v1
```

### 4. Deploy to Atlan
1. Edit `atlan.yaml` and update the `image` field to match your registry URL.
2. Go to **Atlan Admin Center** > **Workflows**.
3. Click **Add Custom Workflow** and upload `atlan.yaml`.

## Local Testing
You can test the logic locally by passing environment variables manually:
```bash
docker run --rm \
  -e TRUSTLOGIX_BASE_URL='[https://demo.trustlogix.io](https://demo.trustlogix.io)' \
  -e TRUSTLOGIX_TENANT_ID='your_id' \
  -e AUTH_METHOD='credentials' \
  -e CLIENT_ID='user@example.com' \
  -e CLIENT_SECRET='password' \
  -e ATLAN_BASE_URL='[https://your-instance.atlan.com](https://your-instance.atlan.com)' \
  -e ATLAN_API_KEY='your-api-token' \
  -v $(pwd)/output:/tmp \
  trustlogix-analyzer
```
