import os
import logging
from collections import Counter
from trustlogix import TrustLogixClient
from atlan_service import AtlanClient
from jinja2 import Environment, FileSystemLoader

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s"
)
logger = logging.getLogger("TrustLogixApp")

# Enable DEBUG for AtlanClient to see BM resolution details
logging.getLogger("AtlanClient").setLevel(logging.DEBUG)


def _is_atlan_configured():
    api_key = os.getenv("ATLAN_API_KEY", "")
    base_url = os.getenv("ATLAN_BASE_URL", "")
    return bool(api_key) and "your-instance" not in base_url


def main():
    try:
        tenant_id = os.getenv("TRUSTLOGIX_TENANT_ID")
        if not tenant_id:
            logger.error("TRUSTLOGIX_TENANT_ID is not set. Aborting.")
            return

        tl_client = TrustLogixClient(tenant_id)
        atlan_client = AtlanClient()

        # -------------------------------------------------------------- #
        #  Step 1: Initialize Atlan
        # -------------------------------------------------------------- #
        atlan_map = {}
        atlan_enabled = _is_atlan_configured()

        if atlan_enabled:
            try:
                logger.info("Initializing Atlan Governance Engine...")
                image_id = atlan_client.upload_images()
                atlan_client.ensure_metadata_def(image_id=image_id)
                atlan_client.ensure_badges()
                atlan_client.ensure_metadata_policy()
                atlan_client.build_tlx_tag_registry()
                atlan_map = atlan_client.get_asset_map()
                logger.info(f"Successfully mapped {len(atlan_map)} asset paths across connections.")
            except Exception as e:
                logger.warning(f"Atlan init warning (continuing without sync): {e}")
                atlan_enabled = False
        else:
            logger.info("Atlan not configured — running in report-only mode.")

        # -------------------------------------------------------------- #
        #  Step 2: Scan TrustLogix
        # -------------------------------------------------------------- #
        logger.info("Starting TrustLogix Scan...")
        tl_accounts = tl_client.get_all_accounts()
        logger.info(f"Found {len(tl_accounts)} active account(s) to scan.")

        domain_groups = {}  # Domain name -> [Account Tree]

        for account in tl_accounts:
            account_name = account.get('name', 'Unknown')
            logger.info(f"Processing account: {account_name}")

            tree = tl_client.build_hierarchy_for_account(account)
            if not tree:
                logger.warning(f"No hierarchy built for {account_name}, skipping.")
                continue

            risk_summary = tree.get("risks_summary", {})

            access_container = next(
                (c for c in tree.get("children", []) if c.get("type") == "ACCESS_CONTAINER"),
                None
            )

            # ---------------------------------------------------------- #
            #  Sync to Atlan & resolve domains per DATABASE
            # ---------------------------------------------------------- #
            found_domains = []

            if atlan_enabled and access_container and access_container.get("children"):
                for db_node in access_container["children"]:
                    db_name = db_node["name"].upper()

                    if db_name in atlan_map:
                        entries = atlan_map[db_name]

                        # Resolve domains from Atlan
                        db_domains = atlan_client.resolve_domains_for_db(db_name, atlan_map)
                        for d in db_domains:
                            found_domains.append(d)

                        if db_domains:
                            logger.info(f"  DB '{db_name}' -> Atlan domain(s): {db_domains}")

                        # Sync BM + Tags to ALL GUIDs for this database
                        synced = 0
                        for entry in entries:
                            ok = atlan_client.update_asset(
                                entry["guid"], risk_summary,
                                type_name=entry.get("typeName", "Table"),
                                asset_name=entry.get("name", ""),
                                qualified_name=entry.get("qualifiedName", ""),
                            )
                            if ok:
                                synced += 1
                            elif atlan_client._should_abort():
                                break

                        if synced > 0:
                            logger.info(f"  Synced '{db_name}' -> {synced} Atlan asset(s).")

                        if atlan_client._should_abort():
                            logger.error("Atlan sync aborted — see error above.")
                            atlan_enabled = False
                            break
                    else:
                        logger.debug(f"  No Atlan match for database '{db_name}'.")

            # ---------------------------------------------------------- #
            #  Determine target domain for this account
            # ---------------------------------------------------------- #
            if found_domains:
                domain_counts = Counter(found_domains)
                target_domain = domain_counts.most_common(1)[0][0]
                logger.info(
                    f"Account '{account_name}' -> domain '{target_domain}' "
                    f"(from {len(found_domains)} DB-level matches)"
                )
            else:
                target_domain = "Unassigned"
                logger.info(f"Account '{account_name}' -> 'Unassigned' (no domain matches)")

            if target_domain not in domain_groups:
                domain_groups[target_domain] = []
            domain_groups[target_domain].append(tree)

        # -------------------------------------------------------------- #
        #  Step 3: Generate Report
        # -------------------------------------------------------------- #
        final_report_data = []
        sorted_domains = sorted(domain_groups.keys(), key=lambda d: (d == "Unassigned", d))

        for domain in sorted_domains:
            accounts = domain_groups[domain]
            dt, dh, dm, dl = 0, 0, 0, 0
            dcats = {}
            for acct in accounts:
                rs = acct.get("risks_summary", {})
                dt += rs.get("total", 0)
                dh += rs.get("high", 0)
                dm += rs.get("medium", 0)
                dl += rs.get("low", 0)
                for cat, cnt in rs.get("categories", {}).items():
                    dcats[cat] = dcats.get(cat, 0) + cnt

            final_report_data.append({
                "name": domain,
                "type": "DOMAIN",
                "rollup": {"total": dt, "high": dh, "medium": dm, "low": dl, "categories": dcats},
                "children": accounts,
            })

        # -------------------------------------------------------------- #
        #  Step 2b: Sync aggregated governance metadata to Atlan Domains
        # -------------------------------------------------------------- #
        if atlan_enabled:
            for domain_data in final_report_data:
                domain_name = domain_data["name"]
                if domain_name == "Unassigned":
                    continue  # No Atlan domain to write to
                rollup = domain_data["rollup"]
                domain_summary = {
                    "total": rollup["total"],
                    "high": rollup["high"],
                    "medium": rollup["medium"],
                    "low": rollup["low"],
                    "categories": rollup.get("categories", {}),
                }
                atlan_client.update_domain(domain_name, domain_summary)

        # Render HTML report
        template_dir = '/app/src/templates'
        if not os.path.isdir(template_dir):
            local = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates")
            template_dir = local if os.path.isdir(local) else os.path.dirname(os.path.abspath(__file__))

        env = Environment(loader=FileSystemLoader(template_dir))
        report_html = env.get_template('report.html').render(tree_data=final_report_data)

        output_path = "/tmp/trustlogix_report.html"
        with open(output_path, "w") as f:
            f.write(report_html)

        logger.info(f"Report generated: {output_path}")

        total_risks = sum(d["rollup"]["total"] for d in final_report_data)
        total_high = sum(d["rollup"]["high"] for d in final_report_data)
        total_accts = sum(len(d["children"]) for d in final_report_data)
        logger.info(
            f"Summary: {total_accts} account(s), {total_risks} risk(s) "
            f"({total_high} high), {len(final_report_data)} domain(s)."
        )
        logger.info("Governance Process Complete.")

    except Exception as e:
        logger.error(f"Fatal execution error: {e}", exc_info=True)


if __name__ == "__main__":
    main()
