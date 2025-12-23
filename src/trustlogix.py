import requests
import logging
import os
import json
import time

class TrustLogixClient:
    def __init__(self, tenant_id):
        self.tenant_id = tenant_id
        self.logger = logging.getLogger("TrustLogixClient")
        
        self.base_url = os.getenv("TRUSTLOGIX_BASE_URL", "").rstrip('/')
        if not self.base_url:
             raise ValueError("TRUSTLOGIX_BASE_URL is missing.")

        self.token = self._authenticate()
        
        self.headers = {
            "Authorization": f"Bearer {self.token}",
            "tenantid": self.tenant_id,
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        }
        
        self.TIMEOUT = 5

    def _authenticate(self):
        method = os.getenv("AUTH_METHOD", "credentials")
        
        if method == "bearer":
            token = os.getenv("TRUSTLOGIX_API_KEY")
            if not token:
                raise ValueError("Auth method is 'bearer' but API Key is missing.")
            return token

        elif method == "credentials":
            username = os.getenv("CLIENT_ID")
            password = os.getenv("CLIENT_SECRET")
            
            login_url = f"{self.base_url}/api/login"
            params = {"userType": "TENANT_USER"}
            
            login_headers = {
                "Content-Type": "application/json",
                "User-Agent": "Mozilla/5.0",
                "Origin": self.base_url,
                "Referer": f"{self.base_url}/login"
            }
            
            payload = {"loginId": username, "password": password}
            
            self.logger.info(f"Logging in to {login_url}...")
            try:
                response = requests.post(login_url, params=params, json=payload, headers=login_headers, timeout=10)
                response.raise_for_status()
                data = response.json()
                
                if "data" in data and "token" in data["data"]:
                    return data["data"]["token"]
                return data["token"]
            except Exception as e:
                self.logger.error(f"Login failed: {str(e)}")
                raise

        return ""

    def get_all_accounts(self):
        endpoint = f"{self.base_url}/api/account"
        params = {
            "status": "Active",
            "page_size": 1000,
            "page_no": 1,
            "includePolicyCount": "true"
        }
        
        try:
            self.logger.info(f"Fetching accounts list...")
            response = requests.get(endpoint, headers=self.headers, params=params, timeout=self.TIMEOUT)
            response.raise_for_status()
            items = response.json().get("items", [])
            
            target_types = ['snowflake', 'databricks']
            filtered_items = [
                item for item in items 
                if item.get('type', '').lower() in target_types
            ]
            
            self.logger.info(f"Found {len(items)} accounts. Processing {len(filtered_items)} valid Snowflake/Databricks accounts.")
            return filtered_items
        except Exception as e:
            self.logger.error(f"Failed to fetch accounts: {str(e)}")
            return []

    def get_databases(self, account_id):
        endpoint = f"{self.base_url}/api/metadata/{account_id}/databases"
        try:
            response = requests.get(endpoint, headers=self.headers, timeout=self.TIMEOUT)
            if response.status_code != 200: 
                return []
            return response.json()
        except Exception:
            return []

    def get_schemas(self, account_id, database_name):
        endpoint = f"{self.base_url}/api/metadata/{account_id}/schemas"
        params = {"databaseNames": database_name}
        try:
            response = requests.get(endpoint, headers=self.headers, params=params, timeout=self.TIMEOUT)
            if response.status_code != 200: return []
            return response.json()
        except Exception:
            return []

    def get_tables(self, account_id, schema_fqdn):
        endpoint = f"{self.base_url}/api/metadata/{account_id}/tables"
        params = {"schemaNames": schema_fqdn}
        try:
            response = requests.get(endpoint, headers=self.headers, params=params, timeout=self.TIMEOUT)
            if response.status_code != 200: return []
            return response.json()
        except Exception:
            return []

    def get_entitlements(self, account_id, object_type, object_name):
        endpoint = f"{self.base_url}/api/account/{account_id}/entitlements"
        all_entitlements = []
        page = 1
        page_size = 100 
        MAX_PAGES = 10 
        
        while page <= MAX_PAGES:
            params = {
                "objectType": object_type,
                "objectName": object_name,
                "includeChildMetadata": "false",
                "page": page,
                "pageSize": page_size
            }
            try:
                response = requests.get(endpoint, headers=self.headers, params=params, timeout=self.TIMEOUT)
                if response.status_code != 200: break
                
                data = response.json()
                
                # Extract and tag roles
                if "roles" in data:
                    for r in data["roles"]:
                        r["entity_type"] = "ROLE"
                        all_entitlements.append(r)

                # Extract and tag users
                if "users" in data:
                    for u in data["users"]:
                        u["entity_type"] = "USER"
                        all_entitlements.append(u)

                # Extract and tag groups
                if "groups" in data:
                    for g in data["groups"]:
                        g["entity_type"] = "GROUP"
                        all_entitlements.append(g)

                if not all_entitlements and page == 1: break
                
                if page >= data.get("totalPages", 0):
                    break
                page += 1
                
            except Exception:
                break
        
        return {"entitlements": all_entitlements}

    def build_hierarchy_for_account(self, account):
        """
        Builds the tree just for ONE account. 
        """
        account_id = account.get('id')
        account_name = account.get('name')
        
        node = {
            "name": account_name,
            "type": "ACCOUNT",
            "subtype": account.get('type'),
            "children": [],
            "entitlements": []
        }
        
        try:
            dbs = self.get_databases(account_id)
        except:
            dbs = []
            
        if not isinstance(dbs, list): return node
        
        # TARGETED DBs
        TARGET_DBS = ['HEALTH_CARE', 'CRM', 'HEALTH_CARE_PAYMENT']
        
        for db in dbs:
            try:
                db_name = db.get('name')
                if db_name not in TARGET_DBS: continue
                
                db_node = {"name": db.get('name'), "type": "DATABASE", "children": [], "entitlements": []}
                # Fetch DB Entitlements
                db_node["entitlements"] = self.get_entitlements(account_id, "DATABASE", db.get('name')).get("entitlements", [])
                
                schemas = self.get_schemas(account_id, db.get('name'))
                if isinstance(schemas, list):
                    for schema in schemas:
                        try:
                            sch_node = {"name": schema.get('name'), "type": "SCHEMA", "children": [], "entitlements": []}
                            sch_node["entitlements"] = self.get_entitlements(account_id, "SCHEMA", schema.get('fullyQualifiedName')).get("entitlements", [])
                            
                            tables = self.get_tables(account_id, schema.get('fullyQualifiedName'))
                            if isinstance(tables, list):
                                for table in tables:
                                    try:
                                        tbl_node = {"name": table.get('name'), "type": "TABLE", "entitlements": []}
                                        tbl_node["entitlements"] = self.get_entitlements(account_id, "TABLE", table.get('fullyQualifiedName')).get("entitlements", [])
                                        sch_node["children"].append(tbl_node)
                                    except: continue
                            
                            db_node["children"].append(sch_node)
                        except: continue
                
                node["children"].append(db_node)
            except: continue
            
        return node