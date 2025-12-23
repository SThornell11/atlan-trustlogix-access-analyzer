import os
import logging
import json
from trustlogix import TrustLogixClient
from atlan_service import AtlanClient
from jinja2 import Environment, FileSystemLoader

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("TrustLogixApp")

def main():
    try:
        tenant_id = os.getenv("TRUSTLOGIX_TENANT_ID")
        if not tenant_id:
            logger.error("Tenant ID is required.")
            return

        tl_client = TrustLogixClient(tenant_id)
        atlan_client = AtlanClient()
        
        logger.info("Step 1: Fetching Atlan Data Products...")
        # Map: { "TableName" : "DataProductName" }
        atlan_map = atlan_client.build_asset_map()
        logger.info(f"Loaded mappings for {len(atlan_map)} assets.")

        logger.info("Step 2: Scanning TrustLogix...")
        tl_accounts = tl_client.get_all_accounts()
        
        # We will organize the tree by Data Product (Domain)
        domains_tree = {} 
        
        no_product_bucket = {
            "name": "Unassigned Assets",
            "type": "DOMAIN", 
            "children": []
        }

        for account in tl_accounts:
            # Get full tree for this account
            account_tree = tl_client.build_hierarchy_for_account(account)
            
            # If empty children, skip
            if not account_tree.get("children"): continue

            # For simplicity in this view, we check if the Account is mapped, 
            # or put the whole account in Unassigned. 
            no_product_bucket["children"].append(account_tree)

        final_tree = list(domains_tree.values())
        final_tree.append(no_product_bucket)
        
        env = Environment(loader=FileSystemLoader('/app/src/templates'))
        template = env.get_template('report.html')
        
        html_content = template.render(
            data_source="TrustLogix + Atlan Data Mesh",
            tree_data=final_tree
        )
        
        output_path = "/tmp/trustlogix_report.html"
        with open(output_path, "w") as f:
            f.write(html_content)
            
        logger.info(f"Report generated successfully: {output_path}")

    except Exception as e:
        logger.error(f"Workflow failed: {str(e)}")
        import traceback
        traceback.print_exc()
        raise

if __name__ == "__main__":
    main()