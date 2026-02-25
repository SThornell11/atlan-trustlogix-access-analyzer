import requests
import logging
import os
import re


class TrustLogixClient:
    SUPPORTED_PLATFORMS = ['snowflake', 'databricks']

    DATABASE_FILTER = []
    ACCOUNT_FILTER = []

    # Schema objectType fallback order per spec §2
    SCHEMA_OBJECT_TYPES = ["DATABASE_SCHEMA", "SCHEMA", "DATA_SCHEMA"]

    def __init__(self, tenant_id):
        self.tenant_id = tenant_id
        self.logger = logging.getLogger("TrustLogixClient")
        self.base_url = os.getenv("TRUSTLOGIX_BASE_URL", "").rstrip('/')
        self.session = requests.Session()
        self.token = self._authenticate()

        self.session.headers.update({
            "Authorization": f"Bearer {self.token}",
            "tenantid": self.tenant_id,
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0",
            "X-Requested-With": "XMLHttpRequest"
        })

        self._refresh_xsrf()
        self.TIMEOUT = 60

    def _refresh_xsrf(self):
        """Refresh XSRF token from session cookies before POST requests."""
        xsrf = self.session.cookies.get('XSRF-TOKEN')
        if xsrf:
            self.session.headers.update({'X-XSRF-TOKEN': xsrf})

    def _authenticate(self):
        """Support both bearer token and username/password authentication (spec §2)."""
        auth_method = os.getenv("AUTH_METHOD", "credentials").lower()

        if auth_method == "bearer":
            token = os.getenv("TRUSTLOGIX_API_KEY", "")
            if not token:
                raise ValueError("AUTH_METHOD=bearer but TRUSTLOGIX_API_KEY is empty.")
            self.logger.info("Authenticated via existing Bearer token.")
            return token

        # Username/Password flow
        login_url = f"{self.base_url}/api/login"
        payload = {
            "loginId": os.getenv("CLIENT_ID"),
            "password": os.getenv("CLIENT_SECRET")
        }
        try:
            res = self.session.post(
                login_url,
                params={"userType": "TENANT_USER"},
                json=payload,
                timeout=20
            )
            res.raise_for_status()
            data = res.json()
            token = data.get("token") or data.get("data", {}).get("token")
            if not token:
                raise ValueError("Login succeeded but no token in response.")
            self.logger.info("Authenticated via username/password.")
            return token
        except Exception as e:
            self.logger.error(f"TrustLogix Login Error: {e}")
            raise

    def get_all_accounts(self):
        try:
            res = self.session.get(
                f"{self.base_url}/api/account",
                params={"status": "Active", "pageSize": 1000},
                timeout=self.TIMEOUT
            )
            res.raise_for_status()
            items = res.json().get("items", [])
            if self.ACCOUNT_FILTER:
                return [i for i in items if i.get('name') in self.ACCOUNT_FILTER]
            return [i for i in items if i.get('type', '').lower() in self.SUPPORTED_PLATFORMS]
        except Exception as e:
            self.logger.error(f"Failed to fetch accounts: {e}")
            return []

    # TrustLogix numeric severity → standard label
    _SEVERITY_MAP = {"1": "CRITICAL", "2": "HIGH", "3": "MEDIUM", "4": "LOW"}

    def get_data_risks(self, account_id):
        """Fetch risks via GET /api/alerts (page_no and page_size are required params).

        CRITICAL: Uses category field as the dynamic category — no fixed buckets.
        Severity is a numeric string: "1"=CRITICAL, "2"=HIGH, "3"=MEDIUM, "4"=LOW.
        """
        items = []
        try:
            res = self.session.get(
                f"{self.base_url}/api/alerts",
                params={
                    "accountId": account_id,
                    "page_no": 1,
                    "page_size": 100,
                    "sort_by": "severity",
                    "sort_order": "DESC",
                },
                timeout=self.TIMEOUT
            )
            if res.status_code == 200:
                items = res.json().get("items", [])
        except Exception as e:
            self.logger.warning(f"GET /api/alerts failed: {e}")

        mapped = []
        for item in items:
            # Use category field directly — dynamic, no fixed buckets
            raw_cat = item.get("category") or item.get("policyRefId") or item.get("alertName") or "Security Alert"
            category = raw_cat.replace("_", " ").title()

            # Map numeric severity ("1"→CRITICAL, "2"→HIGH, "3"→MEDIUM, "4"→LOW)
            sev_raw = str(item.get("severity", "4"))
            severity = self._SEVERITY_MAP.get(sev_raw, sev_raw.upper())

            recommendation = item.get("policyRemediation") or "Review in TrustLogix"
            remediation_meta = item.get("remediationMetaData")
            if isinstance(remediation_meta, list) and len(remediation_meta) > 0:
                first_action = remediation_meta[0].get("displayName", "")
                if first_action and first_action not in ("View Details", "Dismiss"):
                    recommendation = first_action

            mapped.append({
                "severity": severity,
                "category": category,
                "raw_name": raw_cat,
                "details": item.get("details") or item.get("summary") or item.get("description") or "Action required.",
                "recommendation": recommendation
            })
        return mapped

    def _normalize_entitlement(self, entry, entity_type):
        """Normalize entitlement to {name, privileges, entity_type}.

        TrustLogix API may use roleName/userName/groupName instead of name,
        and grantedPrivileges/permissions/accessRights instead of privileges.
        """
        name = (entry.get("name") or
                entry.get("roleName") or
                entry.get("userName") or
                entry.get("userId") or
                entry.get("groupName") or
                entry.get("id") or "Unknown")

        privs = (entry.get("privileges") or
                 entry.get("grantedPrivileges") or
                 entry.get("permissions") or
                 entry.get("accessRights") or
                 [])

        if isinstance(privs, str):
            privs = [p.strip() for p in privs.split(",") if p.strip()]
        elif not isinstance(privs, list):
            privs = []

        return {"name": name, "privileges": privs, "entity_type": entity_type}

    def get_entitlements(self, account_id, object_type, object_name):
        """Fetch entitlements with pageSize=1000 (spec §2)."""
        try:
            res = self.session.get(
                f"{self.base_url}/api/account/{account_id}/entitlements",
                params={
                    "objectType": object_type,
                    "objectName": object_name,
                    "pageSize": 1000  # spec §2: pageSize 1000 for all metadata calls
                },
                timeout=self.TIMEOUT
            )
            if res.status_code == 200:
                data = res.json()
                self.logger.debug(
                    f"Entitlements raw keys for {object_type}/{object_name}: "
                    f"{list(data.keys()) if isinstance(data, dict) else type(data).__name__}"
                )
                all_ents = []
                for key, entity_type in {"roles": "ROLE", "users": "USER", "groups": "GROUP"}.items():
                    entries = data.get(key)
                    if entries and isinstance(entries, list):
                        for entry in entries:
                            if isinstance(entry, dict):
                                all_ents.append(self._normalize_entitlement(entry, entity_type))
                        self.logger.debug(
                            f"  {key}: {len(entries)} entries, "
                            f"first keys: {list(entries[0].keys()) if entries else []}"
                        )
                return all_ents
        except Exception as e:
            self.logger.debug(f"Entitlements fetch failed for {object_type}/{object_name}: {e}")
        return []

    def _get_schema_entitlements(self, account_id, schema_fqn):
        """Try multiple objectType values for schema entitlements (spec §2).
        
        Tries DATABASE_SCHEMA, SCHEMA, and DATA_SCHEMA to ensure compatibility
        across TrustLogix platform versions.
        """
        for obj_type in self.SCHEMA_OBJECT_TYPES:
            ents = self.get_entitlements(account_id, obj_type, schema_fqn)
            if ents:
                self.logger.debug(f"Schema entitlements found via objectType={obj_type}")
                return ents
        return []

    def build_hierarchy_for_account(self, account):
        account_id = account.get('id')
        account_name = account.get('name', 'Unknown')
        risks = self.get_data_risks(account_id)
        summary = self._summarize(risks)

        access_children = []
        try:
            res = self.session.get(
                f"{self.base_url}/api/metadata/{account_id}/databases",
                params={"pageSize": 1000},
                timeout=self.TIMEOUT
            )
            res.raise_for_status()
            dbs = res.json()

            if isinstance(dbs, list):
                for db in dbs:
                    db_name = db.get('name')
                    if not db_name:
                        continue

                    # Apply testing database filter
                    if self.DATABASE_FILTER and db_name.upper() not in [x.upper() for x in self.DATABASE_FILTER]:
                        continue

                    self.logger.info(f"Scanning DB: {db_name} in {account_name}")
                    db_node = {
                        "name": db_name, "type": "DATABASE", "children": [],
                        "entitlements": self.get_entitlements(account_id, "DATABASE", db_name)
                    }

                    try:
                        sch_res = self.session.get(
                            f"{self.base_url}/api/metadata/{account_id}/schemas",
                            params={"databaseNames": db_name, "pageSize": 1000},
                            timeout=self.TIMEOUT
                        )
                        schemas = sch_res.json() if sch_res.status_code == 200 else []
                    except Exception:
                        schemas = []

                    for sch in (schemas if isinstance(schemas, list) else []):
                        sch_name = sch.get('name', '')
                        sch_fqn = sch.get('fullyQualifiedName') or f"{db_name}.{sch_name}"

                        # Use fallback objectType logic for schemas (spec §2)
                        sch_node = {
                            "name": sch_name, "type": "SCHEMA", "children": [],
                            "entitlements": self._get_schema_entitlements(account_id, sch_fqn)
                        }

                        try:
                            tbl_res = self.session.get(
                                f"{self.base_url}/api/metadata/{account_id}/tables",
                                params={"schemaNames": sch_fqn, "pageSize": 1000},
                                timeout=self.TIMEOUT
                            )
                            tables = tbl_res.json() if tbl_res.status_code == 200 else []
                        except Exception:
                            tables = []

                        for tbl in (tables if isinstance(tables, list) else []):
                            tbl_name = tbl.get('name', '')
                            t_fqn = tbl.get('fullyQualifiedName') or f"{sch_fqn}.{tbl_name}"
                            sch_node["children"].append({
                                "name": tbl_name, "type": "TABLE",
                                "entitlements": self.get_entitlements(account_id, "TABLE", t_fqn)
                            })
                        db_node["children"].append(sch_node)
                    access_children.append(db_node)
        except Exception as e:
            self.logger.error(f"Hierarchy error for {account_name}: {e}")

        return {
            "name": account_name, "type": "ACCOUNT",
            "subtype": account.get('type'),
            "risks_summary": summary,
            "children": [
                {"name": "Data Risks", "type": "RISKS_CONTAINER", "risks": risks, "children": []},
                {"name": "Access Analyzer", "type": "ACCESS_CONTAINER", "children": access_children}
            ]
        }

    def _summarize(self, risks):
        """Build a DYNAMIC risk summary — categories come from alertName (spec §2)."""
        summary = {
            "total": len(risks),
            "high": 0, "medium": 0, "low": 0,
            "categories": {}  # Dynamic — populated from actual risk data
        }
        for r in risks:
            sev = r['severity']
            if "HIGH" in sev or "CRITICAL" in sev:
                summary['high'] += 1
            elif "MEDIUM" in sev:
                summary['medium'] += 1
            else:
                summary['low'] += 1

            cat = r['category']
            summary['categories'][cat] = summary['categories'].get(cat, 0) + 1

        return summary