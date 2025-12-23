import os
import requests
import logging
import json

class AtlanClient:
    def __init__(self):
        self.logger = logging.getLogger("AtlanClient")
        self.base_url = os.getenv("ATLAN_BASE_URL", "").rstrip('/')
        self.api_token = os.getenv("ATLAN_API_KEY", "")
        
        self.headers = {
            "Authorization": f"Bearer {self.api_token}",
            "Content-Type": "application/json"
        }

    def get_data_products(self):
        if not self.base_url or not self.api_token:
            return []

        url = f"{self.base_url}/api/meta/search/indexsearch"
        payload = {
            "dsl": {
                "from": 0, "size": 100,
                "query": { "bool": { "filter": [ {"term": {"__state": "ACTIVE"}}, {"term": {"__typeName.keyword": "DataProduct"}} ] } }
            },
            "attributes": ["name", "qualifiedName"] 
        }

        try:
            response = requests.post(url, headers=self.headers, json=payload)
            if response.status_code != 200: return []
            return response.json().get("entities", [])
        except Exception: return []

    def get_assets_for_data_product(self, product_qualified_name):
        if not self.base_url or not self.api_token: return []

        url = f"{self.base_url}/api/meta/search/indexsearch"
        payload = {
            "dsl": {
                "from": 0, "size": 1000,
                "query": {
                    "bool": {
                        "must": [
                            {"term": {"__state": "ACTIVE"}},
                            {"term": {"__typeName.keyword": "Table"}},
                            {"nested": {"path": "__dataProducts", "query": {"term": {"__dataProducts.qualifiedName": product_qualified_name}}}}
                        ]
                    }
                }
            },
            "attributes": ["name"]
        }

        try:
            response = requests.post(url, headers=self.headers, json=payload)
            return response.json().get("entities", [])
        except Exception: return []

    def build_asset_map(self):
        asset_map = {}
        products = self.get_data_products()
        
        for product in products:
            p_name = product["attributes"].get("name")
            p_qname = product["attributes"].get("qualifiedName")
            
            assets = self.get_assets_for_data_product(p_qname)
            for asset in assets:
                t_name = asset["attributes"]["name"] 
                # Map by Table Name to Data Product Name
                asset_map[t_name] = p_name
        
        return asset_map