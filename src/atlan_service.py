import os
import re
import time
import hashlib
import requests
import logging
from datetime import datetime, timezone


class AtlanClient:
    """Atlan integration client for TrustLogix governance metadata.

    Design principles:
      - Tags are FULLY DYNAMIC: created from whatever categories TrustLogix returns
      - BM attributes use displayName-anchored resolution against hashed internals
      - Domain resolution uses domainGUIDs (direct attribute) with GUID->name lookup
      - Fail-fast on 403s to avoid spamming 1000 permission errors
      - Never delete a healthy BM to avoid Persona permission breakage
    """

    # --------------------------------------------------------------------------
    #  Attribute definitions: simple_key -> (displayName, typeName, extra_opts)
    #
    #  The existing 3 in Atlan use: "Total Risks", "High Severity", "Risk Details"
    #  The 5 new ones will be added with isOptional=true.
    # --------------------------------------------------------------------------
    # showInOverview: "true" makes the attribute visible in the asset Overview tab
    # (not just under the dedicated Custom Metadata section)
    ATTR_DEFS = {
        "total_risks":      ("Total Risks",      "int",    {"showInOverview": "true"}),
        "high_severity":    ("High Severity",     "int",    {"showInOverview": "true"}),
        "medium_severity":  ("Medium Severity",   "int",    {}),
        "low_severity":     ("Low Severity",      "int",    {}),
        "risk_categories":  ("Risk Categories",   "string", {}),
        "last_scanned":     ("Last Scanned",      "string", {"showInOverview": "true"}),
        "scan_status":      ("Scan Status",       "string", {"showInOverview": "true"}),
        "risk_details":     ("Risk Details",      "string", {"customType": "textarea"}),
    }
    REQUIRED_ATTRS = list(ATTR_DEFS.keys())

    BADGE_DEFS = {
        "Scan Status": {
            "cm_attr_key": "scan_status",
            "description": "TrustLogix data access governance scan status",
            "conditions": [
                ("eq", '"✓ TrustLogix Data Access Governance Verified"', "#047960"),
                ("neq", '"✓ TrustLogix Data Access Governance Verified"', "#BF1B1B"),
            ],
        },
        "High Severity": {
            "cm_attr_key": "high_severity",
            "description": "Count of high severity risks from TrustLogix",
            "conditions": [
                ("eq",  "0", "#047960"),
                ("gte", "1", "#BF1B1B"),
            ],
        },
        "Total Risks": {
            "cm_attr_key": "total_risks",
            "description": "Total risk count from TrustLogix scan",
            "conditions": [
                ("eq",  "0", "#047960"),
                ("gte", "1", "#F7B43D"),
                ("gte", "5", "#BF1B1B"),
            ],
        },
    }

    LOGO_URL = "https://cdn.prod.website-files.com/689aca9a00606d8ac05c62da/68d41cadacdc5e5594480d4b_TrustLogix_favicon_32x32.png"

    def __init__(self):
        self.logger = logging.getLogger("AtlanClient")
        self.base_url = os.getenv("ATLAN_BASE_URL", "").rstrip('/')
        self.api_token = os.getenv("ATLAN_API_KEY", "")
        self.headers = {
            "Authorization": f"Bearer {self.api_token}",
            "Content-Type": "application/json"
        }
        self.CM_NAME = "TrustLogix Governance"
        self.TAG_PREFIX = "TLX_"

        self._logo_dir = os.path.join(os.path.dirname(__file__), "assets")
        self._logo_small = os.path.join(self._logo_dir, "trustlogix_logo_small.png")

        self._cm_internal_name = None   # hashed BM name e.g. "fhoWmBJgPL77pOZ6vVaeHZ"
        self._attr_names = {}           # simple_key -> hashed internal attr name
        self._created_tags = set()
        self._tlx_tag_names = set()      # all known TLX tag hashed names
        self._domain_guid_map = {}       # domain GUID -> domain display name

        # Fail-fast
        self._consecutive_403 = 0
        self._ABORT_THRESHOLD = 3

    # ------------------------------------------------------------------ #
    #  HTTP helpers
    # ------------------------------------------------------------------ #
    _TIMEOUT = (10, 30)
    _MAX_RETRIES = 3
    _BACKOFF = [2, 5, 10]

    def _request(self, method, endpoint, json_data=None, params=None):
        url = f"{self.base_url}{endpoint}"
        for attempt in range(self._MAX_RETRIES):
            try:
                res = requests.request(
                    method, url,
                    headers=self.headers, json=json_data,
                    params=params, timeout=self._TIMEOUT
                )
                if res.status_code == 403:
                    self._consecutive_403 += 1
                    self.logger.error(f"403 on {endpoint}: {res.text[:300]}")
                    return None
                if res.status_code in [400, 404, 409]:
                    self.logger.debug(f"{endpoint} -> {res.status_code}: {res.text[:300]}")
                    return None
                if res.status_code == 429:
                    wait = int(res.headers.get("Retry-After", self._BACKOFF[attempt]))
                    self.logger.warning(f"Rate limited on {endpoint}, waiting {wait}s...")
                    time.sleep(wait)
                    continue
                if res.status_code >= 500:
                    self.logger.warning(f"{endpoint} -> {res.status_code} (attempt {attempt+1})")
                    time.sleep(self._BACKOFF[attempt])
                    continue
                res.raise_for_status()
                self._consecutive_403 = 0
                return res.json() if res.text.strip() else {"status": "ok"}
            except (requests.exceptions.ConnectionError,
                    requests.exceptions.Timeout) as e:
                self.logger.warning(f"{method} {endpoint} connection error (attempt {attempt+1}): {e}")
                if attempt < self._MAX_RETRIES - 1:
                    time.sleep(self._BACKOFF[attempt])
                    continue
                self.logger.error(f"{method} {endpoint} failed after {self._MAX_RETRIES} attempts.")
                return None
            except requests.exceptions.HTTPError as e:
                body = e.response.text[:500] if e.response is not None else ""
                self.logger.error(f"{method} {endpoint}: {e}\n  {body}")
                return None
            except Exception as e:
                self.logger.error(f"{method} {endpoint}: {e}")
                return None
        self.logger.error(f"{method} {endpoint} exhausted all retries.")
        return None

    def _put(self, endpoint, data, params=None):
        return self._request("PUT", endpoint, json_data=data, params=params)

    def _post(self, endpoint, data, params=None):
        return self._request("POST", endpoint, json_data=data, params=params)

    def _get(self, endpoint, params=None):
        return self._request("GET", endpoint, params=params)

    def _delete(self, endpoint):
        return self._request("DELETE", endpoint)

    def _should_abort(self):
        return self._consecutive_403 >= self._ABORT_THRESHOLD

    # ------------------------------------------------------------------ #
    #  Image Upload
    # ------------------------------------------------------------------ #
    def _ensure_logo_downloaded(self):
        """Download the logo PNG from CDN if not already present locally."""
        if os.path.exists(self._logo_small) and os.path.getsize(self._logo_small) > 0:
            return True
        os.makedirs(self._logo_dir, exist_ok=True)
        try:
            self.logger.info(f"Downloading logo from CDN: {self.LOGO_URL}")
            res = requests.get(self.LOGO_URL, timeout=15)
            if res.status_code == 200 and res.content:
                with open(self._logo_small, "wb") as f:
                    f.write(res.content)
                self.logger.info(f"Logo saved to {self._logo_small} ({len(res.content)} bytes)")
                return True
            self.logger.warning(f"CDN download returned {res.status_code}")
        except Exception as e:
            self.logger.warning(f"Logo download failed: {e}")
        return False

    def upload_images(self):
        if not self._ensure_logo_downloaded():
            self.logger.info("Logo unavailable — BM icon will be set via URL fallback.")
            return None
        try:
            headers = {"Authorization": f"Bearer {self.api_token}"}
            # Try field names used by different Atlan versions
            for field_name in ["file", "image", "logo"]:
                with open(self._logo_small, "rb") as f:
                    files = {field_name: ("trustlogix_logo_small.png", f, "image/png")}
                    res = requests.post(
                        f"{self.base_url}/api/meta/images/upload",
                        headers=headers, files=files, timeout=self._TIMEOUT
                    )
                if res.status_code in [200, 201]:
                    data = res.json() if res.text.strip() else {}
                    img_id = (data.get("id") or data.get("imageId") or
                              data.get("guid") or data.get("imageGuid"))
                    if img_id:
                        self.logger.info(f"Uploaded logo (field='{field_name}'), imageId: {img_id}")
                        return img_id
                    self.logger.debug(f"Upload OK but no id in response: {data}")
                    return None
                self.logger.debug(
                    f"Logo upload (field='{field_name}') returned {res.status_code}: {res.text[:200]}"
                )
        except Exception as e:
            self.logger.debug(f"Logo upload failed: {e}")
        return None

    # ================================================================== #
    #  BM DEFINITION MANAGEMENT
    # ================================================================== #
    # Attributes that should be pinned to the asset Overview tab
    _OVERVIEW_ATTRS = {"Total Risks", "High Severity", "Last Scanned", "Scan Status"}

    def _update_bm_def_options(self, bm_def, image_id=None):
        """Update logo + showInOverview flags on an existing BM definition via PUT.

        Combines both updates into a single PUT to avoid extra round-trips.
        Skips entirely if nothing has changed.
        """
        current_opts = bm_def.get("options") or {}
        desired_logo = image_id or self.LOGO_URL
        current_logo = current_opts.get("imageId") or current_opts.get("logoUrl")
        logo_changed = current_logo != desired_logo

        # Inspect existing attribute defs for missing showInOverview flags
        updated_attrs = []
        attrs_changed = False
        for attr_def in bm_def.get("attributeDefs", []):
            attr_copy = dict(attr_def)
            opts = dict(attr_copy.get("options") or {})
            if (attr_def.get("displayName") in self._OVERVIEW_ATTRS and
                    opts.get("showInOverview") != "true"):
                opts["showInOverview"] = "true"
                attrs_changed = True
            attr_copy["options"] = opts
            updated_attrs.append(attr_copy)

        if not logo_changed and not attrs_changed:
            self.logger.debug("BM logo and overview visibility already up to date.")
            return

        if image_id:
            logo_opts = {"logoType": "image", "imageId": image_id}
        else:
            logo_opts = {"logoType": "image", "logoUrl": self.LOGO_URL}

        bm_copy = {
            "category": bm_def.get("category", "BUSINESS_METADATA"),
            "name": bm_def.get("name"),
            "displayName": bm_def.get("displayName"),
            "description": bm_def.get("description", ""),
            "guid": bm_def.get("guid"),
            "options": {**current_opts, **logo_opts},
            "attributeDefs": updated_attrs,
        }

        result = self._put("/api/meta/types/typedefs", {"businessMetadataDefs": [bm_copy]})
        if result:
            changes = []
            if logo_changed:
                changes.append("logo")
            if attrs_changed:
                changes.append("showInOverview for key attributes")
            self.logger.info(f"Updated BM definition: {', '.join(changes)}")
        else:
            self.logger.warning(
                "Could not update BM definition options via API. "
                "Manual fix: Atlan Admin → Governance → Custom Metadata → "
                "TrustLogix Governance → edit each attribute → enable 'Show in overview'."
            )

    def ensure_metadata_def(self, image_id=None):
        entity_types = '["Table","View","MaterialisedView","Database","Schema","Column","DataDomain"]'
        existing = self._find_existing_bm_def()

        if existing:
            internal_name = existing.get("name", "")
            self.logger.info(f"Found existing BM def: '{internal_name}'")

            if self._bm_has_entity_types(existing):
                self._cm_internal_name = internal_name
                self._resolve_attr_names(existing)

                missing = [k for k in self.REQUIRED_ATTRS if k not in self._attr_names]
                if missing:
                    self.logger.info(f"Adding {len(missing)} missing BM attributes: {missing}")
                    self._add_missing_attributes(existing, missing, entity_types)
                    time.sleep(2)
                    refreshed = self._find_existing_bm_def()
                    if refreshed:
                        self._resolve_attr_names(refreshed)

                # Ensure DataDomain is in applicableEntityTypes
                self._ensure_entity_types_include(existing, entity_types)

                # Always try to set/update logo + showInOverview on existing BM def
                self._update_bm_def_options(existing, image_id=image_id)

                n = len(self._attr_names)
                self.logger.info(f"BM ready with {n}/{len(self.REQUIRED_ATTRS)} resolved attributes.")
                return

            self.logger.warning(f"BM '{internal_name}' missing applicableEntityTypes. Recreating...")
            self._delete_bm_def(internal_name)

        self.logger.info("Creating new BM definition...")
        self._create_new_bm_def(entity_types, image_id=image_id)

    def _bm_has_entity_types(self, bm_def):
        attrs = bm_def.get("attributeDefs", [])
        if not attrs:
            return False
        return all(attr.get("options", {}).get("applicableEntityTypes") for attr in attrs)

    def _ensure_entity_types_include(self, bm_def, desired_entity_types):
        """Ensure all BM attributes have the full set of applicableEntityTypes.

        If existing attributes are missing types (e.g. DataDomain was added),
        update the typedef so BM can be written to those entity types.
        """
        needs_update = False
        for attr_def in bm_def.get("attributeDefs", []):
            current = attr_def.get("options", {}).get("applicableEntityTypes", "")
            if "DataDomain" not in current:
                needs_update = True
                break

        if not needs_update:
            return

        self.logger.info("Updating BM typedef to include DataDomain in applicableEntityTypes...")
        updated_attrs = []
        for attr_def in bm_def.get("attributeDefs", []):
            attr_copy = dict(attr_def)
            opts = dict(attr_copy.get("options", {}))
            opts["applicableEntityTypes"] = desired_entity_types
            attr_copy["options"] = opts
            updated_attrs.append(attr_copy)

        payload = {"businessMetadataDefs": [{
            "category": bm_def.get("category", "BUSINESS_METADATA"),
            "name": bm_def.get("name"),
            "displayName": bm_def.get("displayName"),
            "description": bm_def.get("description", ""),
            "guid": bm_def.get("guid"),
            "attributeDefs": updated_attrs,
        }]}

        result = self._put("/api/meta/types/typedefs", payload)
        if result:
            self.logger.info("Updated BM typedef with DataDomain entity type.")
        else:
            self.logger.warning("Failed to update BM typedef with DataDomain.")

    def _find_existing_bm_def(self):
        data = self._get("/api/meta/types/typedefs", params={"type": "business_metadata"})
        if not data:
            return None
        for bm in data.get("businessMetadataDefs", []):
            if bm.get("displayName") == "TrustLogix Governance":
                return bm
        return None

    def _delete_bm_def(self, internal_name):
        try:
            res = requests.delete(
                f"{self.base_url}/api/meta/types/typedef/name/{internal_name}",
                headers=self.headers, timeout=self._TIMEOUT
            )
            if res.status_code in [200, 204]:
                self.logger.info(f"Deleted BM def: '{internal_name}'")
                time.sleep(2)
                return True
            self.logger.error(f"Delete failed: {res.status_code} — {res.text[:500]}")
        except Exception as e:
            self.logger.error(f"Delete exception: {e}")
        return False

    def _create_new_bm_def(self, entity_types, image_id=None):
        base_opts = {
            "applicableEntityTypes": entity_types,
            "maxStrLength": "100000000"
        }
        attr_defs = []
        for key, (display, type_name, extra) in self.ATTR_DEFS.items():
            opts = {**base_opts, **extra}
            attr_defs.append({
                "name": key,
                "displayName": display,
                "typeName": type_name,
                "isOptional": True,
                "options": opts
            })

        # Use uploaded imageId if available, otherwise fall back to URL
        if image_id:
            logo_opts = {"logoType": "image", "imageId": image_id}
        else:
            logo_opts = {"logoType": "image", "logoUrl": self.LOGO_URL}

        payload = {
            "businessMetadataDefs": [{
                "category": "BUSINESS_METADATA",
                "name": self.CM_NAME,
                "displayName": "TrustLogix Governance",
                "description": "Security risk and access governance metadata from TrustLogix.",
                "options": logo_opts,
                "attributeDefs": attr_defs
            }]
        }
        self.logger.info(f"POST typedefs with {len(attr_defs)} attributes")
        result = self._post("/api/meta/types/typedefs", payload)
        if result:
            self.logger.info("Created new BM definition.")
        else:
            self.logger.warning("BM POST returned None (409 or error).")

        time.sleep(2)
        found = self._find_existing_bm_def()
        if found:
            self._cm_internal_name = found["name"]
            self._resolve_attr_names(found)
            self.logger.info(
                f"VERIFIED: BM '{self._cm_internal_name}' — "
                f"{len(found.get('attributeDefs', []))} attributes."
            )
        else:
            self._cm_internal_name = None
            self.logger.error("Could not find BM after creation.")

    def _add_missing_attributes(self, bm_def, missing_keys, entity_types):
        """Add missing attributes with isOptional=true to avoid 'mandatory attr' error."""
        base_opts = {
            "applicableEntityTypes": entity_types,
            "maxStrLength": "100000000"
        }
        new_attrs = []
        for key in missing_keys:
            if key not in self.ATTR_DEFS:
                continue
            display, type_name, extra = self.ATTR_DEFS[key]
            opts = {**base_opts, **extra}
            new_attrs.append({
                "name": key,
                "displayName": display,
                "typeName": type_name,
                "isOptional": True,
                "cardinality": "SINGLE",
                "valuesMinCount": 0,
                "valuesMaxCount": 1,
                "options": opts
            })

        if not new_attrs:
            return

        # Clone existing attrs and append new ones
        existing_attrs = list(bm_def.get("attributeDefs", []))
        all_attrs = existing_attrs + new_attrs

        # Build the full typedef payload — include all existing BM fields
        bm_copy = {
            "category": bm_def.get("category", "BUSINESS_METADATA"),
            "name": bm_def.get("name"),
            "displayName": bm_def.get("displayName"),
            "description": bm_def.get("description", ""),
            "guid": bm_def.get("guid"),
            "attributeDefs": all_attrs,
        }

        payload = {"businessMetadataDefs": [bm_copy]}

        self.logger.info(f"PUT typedefs: adding {len(new_attrs)} optional attrs -> {len(all_attrs)} total")
        result = self._put("/api/meta/types/typedefs", payload)
        if result:
            self.logger.info(f"Successfully added {len(new_attrs)} missing attributes.")
        else:
            self.logger.error(
                "Failed to add missing attributes. "
                "You may need to add them manually in Atlan UI: "
                "Go to Admin > Custom Metadata > TrustLogix Governance > Add properties: "
                + ", ".join(f"'{self.ATTR_DEFS[k][0]}' ({self.ATTR_DEFS[k][1]})" for k in missing_keys if k in self.ATTR_DEFS)
            )

    # ================================================================== #
    #  BADGE MANAGEMENT — idempotent create/update on each run
    # ================================================================== #
    def ensure_badges(self):
        """Create or update badges for key BM attributes. Idempotent."""
        if not self._cm_internal_name:
            self.logger.warning("Cannot create badges: BM name not resolved.")
            return
        existing_badges = self._find_existing_badges()
        for badge_name, badge_def in self.BADGE_DEFS.items():
            attr_key = badge_def["cm_attr_key"]
            hashed_attr = self._attr_names.get(attr_key)
            if not hashed_attr:
                continue
            full_attr = f"{self._cm_internal_name}.{hashed_attr}"
            qn = f"badges/global/{full_attr}"
            if qn in existing_badges:
                self.logger.debug(f"Badge '{badge_name}' already exists, updating conditions.")
                self._update_badge(existing_badges[qn], badge_name, badge_def, full_attr, qn)
            else:
                self._create_badge(badge_name, badge_def, full_attr, qn)

    def _find_existing_badges(self):
        badges = {}
        try:
            data = self._post("/api/meta/search/indexsearch", {
                "dsl": {"from": 0, "size": 50, "query": {"bool": {"filter": [
                    {"terms": {"__typeName.keyword": ["Badge"]}}
                ]}}},
                "attributes": ["name", "qualifiedName", "badgeMetadataAttribute"]
            })
            if data and "entities" in data:
                for ent in data["entities"]:
                    qn = ent.get("attributes", {}).get("qualifiedName", "")
                    guid = ent.get("guid", "")
                    if qn and guid:
                        badges[qn] = guid
        except Exception as e:
            self.logger.debug(f"Badge search failed: {e}")
        self.logger.info(f"Found {len(badges)} existing badge(s).")
        return badges

    def _create_badge(self, badge_name, badge_def, full_attr, qn):
        conditions = [{"badgeConditionOperator": op, "badgeConditionValue": val,
                       "badgeConditionColorhex": color}
                      for op, val, color in badge_def["conditions"]]
        result = self._post("/api/meta/entity/bulk", {"entities": [{
            "typeName": "Badge",
            "attributes": {"name": badge_name, "badgeMetadataAttribute": full_attr,
                           "qualifiedName": qn,
                           "userDescription": badge_def.get("description", ""),
                           "badgeConditions": conditions}
        }]})
        if result:
            self.logger.info(f"Created badge: '{badge_name}' -> {qn}")
        else:
            self.logger.warning(f"Failed to create badge: '{badge_name}'")

    def _update_badge(self, badge_guid, badge_name, badge_def, full_attr, qn):
        conditions = [{"badgeConditionOperator": op, "badgeConditionValue": val,
                       "badgeConditionColorhex": color}
                      for op, val, color in badge_def["conditions"]]
        result = self._post("/api/meta/entity/bulk", {"entities": [{
            "typeName": "Badge", "guid": badge_guid,
            "attributes": {"name": badge_name, "qualifiedName": qn,
                           "badgeMetadataAttribute": full_attr,
                           "badgeConditions": conditions}
        }]})
        if result:
            self.logger.debug(f"Updated badge conditions for '{badge_name}'")

    # ================================================================== #
    #  PERSONA METADATA POLICY — enable sidebar visibility
    # ================================================================== #
    def ensure_metadata_policy(self):
        """Ensure the Default persona has a metadata policy to view TrustLogix
        Governance custom metadata in the asset sidebar.

        Atlan denies access by default; without a policy users cannot see the
        TrustLogix Governance section in the right-hand sidebar.
        """
        if not self._cm_internal_name:
            self.logger.warning("Cannot ensure metadata policy: BM not resolved.")
            return

        persona_guid, persona_qn = self._find_default_persona()
        if not persona_guid:
            self.logger.warning("Could not find any Persona in Atlan.")
            self._log_manual_policy_instructions()
            return

        self.logger.info(f"Checking TrustLogix metadata policy on persona: {persona_guid}")

        if self._tlx_policy_exists(persona_guid):
            self.logger.info("TrustLogix metadata policy already exists on Default persona.")
            return

        self._create_metadata_policy(persona_guid, persona_qn)

    def _find_default_persona(self):
        """Search for the Default persona; return (guid, qualifiedName)."""
        data = self._post("/api/meta/search/indexsearch", {
            "dsl": {
                "from": 0, "size": 20,
                "query": {"bool": {"filter": [
                    {"terms": {"__typeName.keyword": ["Persona"]}}
                ]}}
            },
            "attributes": ["name", "qualifiedName"]
        })
        if not data or "entities" not in data:
            return None, None

        entities = data.get("entities", [])
        # Prefer the persona named "Default"
        for ent in entities:
            name = ent.get("attributes", {}).get("name", "")
            if name.lower() == "default":
                return ent.get("guid"), ent.get("attributes", {}).get("qualifiedName", "")
        # Fall back to the first persona
        if entities:
            ent = entities[0]
            self.logger.debug(
                f"No 'Default' persona found; using '{ent.get('attributes',{}).get('name','?')}'"
            )
            return ent.get("guid"), ent.get("attributes", {}).get("qualifiedName", "")
        return None, None

    def _tlx_policy_exists(self, persona_guid):
        """Return True if a TrustLogix metadata policy already exists on this persona."""
        data = self._get(
            f"/api/meta/entity/guid/{persona_guid}",
            params={"minExtInfo": "false", "ignoreRelationships": "false"}
        )
        if not data:
            return False
        # Check referredEntities (policies show up here when relationships=true)
        for ref in data.get("referredEntities", {}).values():
            ref_name = ref.get("attributes", {}).get("name", "")
            if "trustlogix" in ref_name.lower() or "tlx-view" in ref_name.lower():
                self.logger.debug(f"Found existing TLX policy: '{ref_name}'")
                return True
        return False

    def _get_connection_resources(self):
        """Return a list of policyResources strings for all known connections."""
        data = self._post("/api/meta/search/indexsearch", {
            "dsl": {
                "from": 0, "size": 50,
                "query": {"bool": {"filter": [
                    {"terms": {"__typeName.keyword": ["Connection"]}}
                ]}}
            },
            "attributes": ["qualifiedName"]
        })
        resources = []
        if data and "entities" in data:
            for ent in data["entities"]:
                qn = ent.get("attributes", {}).get("qualifiedName", "")
                if qn:
                    resources.append(f"entity:{qn}")
        if not resources:
            # Fallback: use the resource format seen in existing policies
            resources = ["entity:default/snowflake/1768577943"]
            self.logger.debug("No connections found; using fallback resource.")
        self.logger.debug(f"Policy resources: {resources}")
        return resources

    def _create_metadata_policy(self, persona_guid, persona_qn):
        """Create an AuthPolicy on the given persona granting view access to
        TrustLogix Governance custom metadata."""
        suffix = hashlib.md5(persona_guid.encode()).hexdigest()[:8]
        policy_name = "TrustLogix Governance - View Custom Metadata"
        base_qn = persona_qn.rstrip("/") if persona_qn else "default"
        policy_qn = f"{base_qn}/metadata/tlx-view-{suffix}"

        resources = self._get_connection_resources()

        payload = {
            "entities": [{
                "typeName": "AuthPolicy",
                "attributes": {
                    "name": policy_name,
                    "qualifiedName": policy_qn,
                    "policyType": "allow",
                    "policyCategory": "persona",
                    "policySubCategory": "metadata",
                    "policyServiceName": "atlas",
                    "policyActions": [
                        "persona-asset-read",
                        "persona-business-update-metadata",
                    ],
                    "policyResources": resources,
                    "policyConditions": [],
                    "isPolicyEnabled": True,
                    "policyPriority": 0,
                },
                "relationshipAttributes": {
                    "accessControl": {
                        "typeName": "Persona",
                        "guid": persona_guid,
                    }
                }
            }]
        }

        result = self._post("/api/meta/entity/bulk", payload)
        if result:
            self.logger.info(
                f"Created metadata policy '{policy_name}' on Default persona — "
                "TrustLogix Governance should now appear in the Atlan asset sidebar."
            )
        else:
            self.logger.warning(
                "Could not create metadata policy via API "
                "(your token may not have persona admin permissions)."
            )
            self._log_manual_policy_instructions()

    def _log_manual_policy_instructions(self):
        self.logger.warning(
            "Manual step needed to show TrustLogix Governance in the Atlan sidebar:\n"
            "  1. Atlan Admin → Governance → Personas\n"
            "  2. Click the 'Default' persona\n"
            "  3. Policies tab → Add policy → Metadata policy\n"
            "  4. Name: 'TrustLogix Governance - View'\n"
            "  5. Actions: enable 'View'\n"
            "  6. Custom metadata: select 'TrustLogix Governance'\n"
            "  7. Assets: All assets → Save"
        )

    # ------------------------------------------------------------------ #
    #  Attribute Name Resolution — matches on displayName
    # ------------------------------------------------------------------ #
    def _resolve_attr_names(self, bm_def):
        """Map simple keys -> hashed names using displayName matching."""
        self._cm_internal_name = bm_def.get("name", self._cm_internal_name)
        self._attr_names = {}

        display_to_hashed = {}
        for attr_def in bm_def.get("attributeDefs", []):
            dn = attr_def.get("displayName", "")
            hn = attr_def.get("name", "")
            archived = attr_def.get("options", {}).get("isArchived", "false")
            if dn and hn and str(archived).lower() != "true":
                display_to_hashed[dn] = hn

        self.logger.debug(f"BM attributes in Atlan: {list(display_to_hashed.keys())}")

        for simple_key, (expected_display, _, _) in self.ATTR_DEFS.items():
            if expected_display in display_to_hashed:
                self._attr_names[simple_key] = display_to_hashed[expected_display]

        self.logger.info(f"Attribute mapping: {len(self._attr_names)}/{len(self.REQUIRED_ATTRS)} resolved")
        for k, v in self._attr_names.items():
            self.logger.debug(f"  {k} -> {v}")

        if len(self._attr_names) < len(self.REQUIRED_ATTRS):
            missing = set(self.REQUIRED_ATTRS) - set(self._attr_names.keys())
            self.logger.warning(f"Unresolved (will be added): {missing}")

    # ================================================================== #
    #  DOMAIN GUID -> NAME RESOLUTION
    # ================================================================== #
    def _build_domain_guid_map(self):
        """Search for all DataDomain entities and build GUID -> {name, qualifiedName} lookup."""
        self._domain_guid_map = {}
        try:
            data = self._post("/api/meta/search/indexsearch", {
                "dsl": {
                    "from": 0, "size": 100,
                    "query": {"bool": {"filter": [
                        {"terms": {"__typeName.keyword": ["DataDomain"]}}
                    ]}}
                },
                "attributes": ["name", "qualifiedName"]
            })
            if data and "entities" in data:
                for ent in data["entities"]:
                    guid = ent.get("guid")
                    attrs = ent.get("attributes", {})
                    name = attrs.get("name", "")
                    qn = attrs.get("qualifiedName", "")
                    if guid and name:
                        self._domain_guid_map[guid] = {
                            "name": name,
                            "qualifiedName": qn,
                        }

            self.logger.info(f"Domain GUID map: {{{', '.join(repr(k)+': '+repr(v['name']) for k,v in self._domain_guid_map.items())}}}")
        except Exception as e:
            self.logger.warning(f"Failed to build domain GUID map: {e}")

    def _resolve_domain_from_guids(self, domain_guids):
        """Resolve a list of domain GUIDs to a domain display name."""
        if not domain_guids:
            return "Unassigned"
        if isinstance(domain_guids, str):
            domain_guids = [domain_guids]
        for guid in domain_guids:
            info = self._domain_guid_map.get(guid)
            if info:
                return info["name"]
        return "Unassigned"

    # ================================================================== #
    #  DYNAMIC TAG MANAGEMENT
    #
    #  On each sync we:
    #    1. Ensure tag typedefs exist for the current risk categories
    #    2. Build a registry of ALL known TLX_ tag hashed names
    #    3. Per asset: strip any existing TLX_ tags, then apply the new set
    #  This ensures stale tags from previous scans are cleaned up
    #  without touching any non-TrustLogix tags on the asset.
    # ================================================================== #
    @staticmethod
    def _make_tag_id(category_name):
        safe = re.sub(r'[^A-Za-z0-9]+', '_', category_name).strip('_').upper()
        return f"TLX_{safe}"

    def build_tlx_tag_registry(self):
        """Scan all classification typedefs and register any TLX_ tags.

        Populates _tlx_tag_names: set of hashed names for all TrustLogix tags.
        Call this once during init so we know which tags to strip.
        """
        self._tlx_tag_names = set()
        existing = self._get("/api/meta/types/typedefs", params={"type": "classification"})
        if existing:
            for cdef in existing.get("classificationDefs", []):
                name = cdef.get("name", "")
                display = cdef.get("displayName", "")
                # Match tags we created: either name starts with TLX_
                # or displayName starts with "TrustLogix" or "TLX"
                if (name.startswith("TLX_") or
                        display.startswith("TrustLogix") or
                        display.startswith("TLX")):
                    self._tlx_tag_names.add(name)
                    self._created_tags.add(name)
        self.logger.info(f"TLX tag registry: {len(self._tlx_tag_names)} known tag(s)")

    def ensure_dynamic_tag(self, category_name):
        tag_id = self._make_tag_id(category_name)
        if tag_id in self._created_tags:
            return tag_id

        existing = self._get("/api/meta/types/typedefs", params={"type": "classification"})
        if existing:
            for cdef in existing.get("classificationDefs", []):
                if cdef.get("name") == tag_id or cdef.get("displayName") == category_name:
                    actual = cdef.get("name", tag_id)
                    self._created_tags.add(actual)
                    self._tlx_tag_names.add(actual)
                    return actual

        color = "Red" if any(kw in category_name.lower() for kw in [
            "critical", "exfiltrat", "breach", "shadow", "high"
        ]) else "Orange"

        payload = {
            "classificationDefs": [{
                "category": "CLASSIFICATION",
                "name": tag_id,
                "displayName": category_name,
                "description": f"TrustLogix risk category: {category_name}",
                "options": {"color": color}
            }]
        }
        result = self._post("/api/meta/types/typedefs", payload)
        if result:
            created = result.get("classificationDefs", [])
            if created:
                actual = created[0].get("name", tag_id)
                self._created_tags.add(actual)
                self._tlx_tag_names.add(actual)
                self.logger.info(f"Created tag: {actual} ({category_name}, {color})")
                return actual
        self._created_tags.add(tag_id)
        self._tlx_tag_names.add(tag_id)
        return tag_id

    def ensure_rollup_tag(self, summary):
        high = summary.get("high", 0)
        total = summary.get("total", 0)
        if high > 0:
            return self.ensure_dynamic_tag("TrustLogix High Risk")
        elif total > 0:
            return self.ensure_dynamic_tag("TrustLogix Risks Detected")
        else:
            return self.ensure_dynamic_tag("TrustLogix Data Access Governance Verified")

    def _sync_tags_on_asset(self, guid, desired_tag_names):
        """Reset TLX tags on an asset: remove stale ones, add new ones.

        Only touches tags in self._tlx_tag_names — leaves all other
        (non-TrustLogix) tags untouched.

        Args:
            guid: asset GUID
            desired_tag_names: set of hashed tag names that SHOULD be on this asset
        """
        # 1. Get current classifications on this asset
        current_tlx = set()
        try:
            entity_data = self._get(f"/api/meta/entity/guid/{guid}",
                                    params={"minExtInfo": "false", "ignoreRelationships": "true"})
            if entity_data:
                entity = entity_data.get("entity", entity_data)
                classifications = entity.get("classifications", [])
                for c in classifications:
                    type_name = c.get("typeName", "")
                    if type_name in self._tlx_tag_names:
                        current_tlx.add(type_name)
        except Exception as e:
            self.logger.debug(f"Could not read classifications for {guid}: {e}")

        # 2. Remove TLX tags that shouldn't be there anymore
        to_remove = current_tlx - desired_tag_names
        for tag_name in to_remove:
            self._delete(f"/api/meta/entity/guid/{guid}/classification/{tag_name}")
            self.logger.debug(f"Removed stale tag '{tag_name}' from {guid}")

        # 3. Add TLX tags that aren't already on the asset
        to_add = desired_tag_names - current_tlx
        if to_add:
            tags_payload = [{"typeName": t, "propagate": True} for t in to_add]
            result = self._post(f"/api/meta/entity/guid/{guid}/classifications", tags_payload)
            if result is not None:
                self.logger.debug(f"Applied {len(to_add)} tag(s) to {guid}")
            else:
                self.logger.debug(f"Tag apply returned None for {guid} (may already exist)")

        if not to_remove and not to_add:
            self.logger.debug(f"Tags unchanged for {guid}")

    # ================================================================== #
    #  ASSET INDEX WITH DOMAIN RESOLUTION VIA domainGUIDs
    # ================================================================== #
    def get_asset_map(self):
        """Build mapping: DATABASE_NAME (upper) -> [{guid, domain, typeName, ...}].

        Domain resolution uses `domainGUIDs` (a direct attribute containing
        DataDomain GUIDs) resolved against the domain GUID->name lookup.
        """
        # First, build the GUID -> name lookup
        self._build_domain_guid_map()

        mapping = {}
        page_size = 100
        offset = 0

        while True:
            payload = {
                "dsl": {
                    "from": offset, "size": page_size,
                    "query": {"bool": {"filter": [
                        {"terms": {"__typeName.keyword": [
                            "Table", "View", "MaterialisedView", "Database", "Schema"
                        ]}}
                    ]}}
                },
                "attributes": [
                    "name", "databaseName", "schemaName",
                    "qualifiedName", "connectionName",
                    # THE KEY FIELD: domainGUIDs is a direct attribute
                    # containing DataDomain GUIDs on each asset
                    "domainGUIDs",
                    # Also request productGUIDs for additional context
                    "productGUIDs",
                ]
            }
            data = self._post("/api/meta/search/indexsearch", payload)
            if not data or "entities" not in data:
                break

            entities = data.get("entities", [])
            if not entities:
                break

            for entity in entities:
                attrs = entity.get("attributes", {})
                db = (attrs.get('databaseName') or attrs.get('name', '')).upper()
                if not db:
                    continue

                # Resolve domain from domainGUIDs
                domain_guids = attrs.get("domainGUIDs")
                domain = self._resolve_domain_from_guids(domain_guids)

                guid = entity.get("guid")
                if not guid:
                    continue

                if db not in mapping:
                    mapping[db] = []
                mapping[db].append({
                    "guid": guid,
                    "domain": domain,
                    "typeName": entity.get("typeName", "Table"),
                    "name": attrs.get("name", ""),
                    "qualifiedName": attrs.get("qualifiedName", ""),
                    "connectionName": attrs.get("connectionName", ""),
                })

            total_count = data.get("approximateCount", 0)
            offset += page_size
            if offset >= total_count:
                break

        # Log domain distribution
        domain_counts = {}
        for entries in mapping.values():
            for e in entries:
                d = e.get("domain", "Unassigned")
                domain_counts[d] = domain_counts.get(d, 0) + 1
        self.logger.info(
            f"Indexed {len(mapping)} database paths "
            f"({sum(len(v) for v in mapping.values())} GUIDs). "
            f"Domain distribution: {domain_counts}"
        )
        return mapping

    def resolve_domains_for_db(self, db_name_upper, atlan_map):
        entries = atlan_map.get(db_name_upper, [])
        return {e["domain"] for e in entries if e.get("domain", "Unassigned") != "Unassigned"}

    # ================================================================== #
    #  ASSET UPDATE — always writes BM, even for 0 risks
    # ================================================================== #
    def update_asset(self, guid, summary, type_name="Table", asset_name="", qualified_name=""):
        cm = self._cm_internal_name
        if not cm:
            self.logger.error(f"Cannot update {guid}: BM name not resolved.")
            return False
        if self._should_abort():
            return False

        total = summary.get('total', 0)
        high = summary.get('high', 0)
        medium = summary.get('medium', 0)
        low = summary.get('low', 0)
        cats = summary.get('categories', {})
        now = datetime.now(timezone.utc).strftime("%b %d, %Y %H:%M UTC")

        if total > 0:
            cat_lines = [f"{k}: {v}" for k, v in cats.items() if v > 0]
            risk_text = "\n".join(cat_lines) if cat_lines else "Risks detected"
            scan_status = f"{total} Risk{'s' if total != 1 else ''} Found"
            if high > 0:
                scan_status = f"⚠ {high} High | {medium} Med | {low} Low"
        else:
            risk_text = "No risks detected. TrustLogix data access governance verified."
            scan_status = "✓ TrustLogix Data Access Governance Verified"

        categories_text = ", ".join(cats.keys()) if cats else "None"

        # Build payload using RESOLVED hashed attribute names
        # Only include attributes that actually resolved
        attr_data = {
            "total_risks":     total,
            "high_severity":   high,
            "medium_severity": medium,
            "low_severity":    low,
            "risk_categories": categories_text,
            "last_scanned":    now,
            "scan_status":     scan_status,
            "risk_details":    risk_text,
        }

        bm_values = {}
        for key, value in attr_data.items():
            hashed = self._attr_names.get(key)
            if hashed:
                bm_values[hashed] = value

        if not bm_values:
            self.logger.warning(f"No resolved attributes for {guid}. attr_names={self._attr_names}")
            return False

        self.logger.debug(f"Writing BM to {guid}: {len(bm_values)} attrs, status='{scan_status}'")

        result = self._post(
            f"/api/meta/entity/guid/{guid}/businessmetadata",
            {cm: bm_values},
            params={"isOverwrite": "true"}
        )

        if result is not None:
            self.logger.debug(f"Updated BM for {guid}")
        else:
            self.logger.warning(f"BM update failed for {guid}")

        if self._should_abort():
            self.logger.error(
                f"ABORTING: {self._consecutive_403} consecutive 403s. "
                "Your API token Persona needs 'Business Metadata' write permission."
            )
            return False

        # --- Tags: build desired set, then sync (remove stale + add new) ---
        if result is not None:
            desired_tags = set()

            # Rollup tag (always)
            rollup_tag = self.ensure_rollup_tag(summary)
            if rollup_tag:
                desired_tags.add(rollup_tag)

            # Category tags (only when risks exist)
            if total > 0:
                for cat, count in cats.items():
                    if count > 0:
                        tag_id = self.ensure_dynamic_tag(cat)
                        if tag_id:
                            desired_tags.add(tag_id)

            self._sync_tags_on_asset(guid, desired_tags)

        # --- Announcement: colored banner at top of asset overview ---
        if result is not None:
            self._set_announcement(guid, summary, now, type_name, asset_name, qualified_name)

        return result is not None

    def _set_announcement(self, guid, summary, timestamp,
                          type_name="Table", asset_name="", qualified_name=""):
        """Set an Atlan announcement banner on the asset.

        IMPORTANT: Atlan entity updates require typeName, name, AND
        qualifiedName — all mandatory Referenceable/Asset fields.
        """
        if not qualified_name or not asset_name:
            self.logger.debug(f"Skipping announcement for {guid}: missing name or qualifiedName.")
            return
        total = summary.get("total", 0)
        high = summary.get("high", 0)
        medium = summary.get("medium", 0)
        low = summary.get("low", 0)
        cats = summary.get("categories", {})

        if high > 0:
            ann_type = "issue"
            ann_title = f"TrustLogix: {high} High Severity Risk{'s' if high != 1 else ''} Detected"
            lines = [f"⚠ {total} total risk{'s' if total != 1 else ''}: {high} high, {medium} medium, {low} low"]
            if cats:
                lines.append("Categories: " + ", ".join(f"{k} ({v})" for k, v in cats.items() if v > 0))
            lines.append(f"Last scanned: {timestamp}")
            ann_message = "\n".join(lines)

        elif total > 0:
            ann_type = "warning"
            ann_title = f"TrustLogix: {total} Risk{'s' if total != 1 else ''} Detected"
            lines = [f"{medium} medium, {low} low severity"]
            if cats:
                lines.append("Categories: " + ", ".join(f"{k} ({v})" for k, v in cats.items() if v > 0))
            lines.append(f"Last scanned: {timestamp}")
            ann_message = "\n".join(lines)

        else:
            ann_type = "information"
            ann_title = "TrustLogix: Data Access Governance Verified"
            ann_message = f"No security risks detected. Data access governance verified. Last scanned: {timestamp}"

        payload = {
            "entity": {
                "typeName": type_name,
                "guid": guid,
                "attributes": {
                    "name": asset_name,
                    "qualifiedName": qualified_name,
                    "announcementType": ann_type,
                    "announcementTitle": ann_title,
                    "announcementMessage": ann_message,
                }
            }
        }

        result = self._post(f"/api/meta/entity", payload)
        if result is not None:
            self.logger.debug(f"Set {ann_type} announcement on {guid}: {ann_title}")
        else:
            self.logger.debug(f"Announcement update failed for {guid}")

    # ================================================================== #
    #  DOMAIN-LEVEL METADATA — aggregate risk data onto DataDomain entities
    # ================================================================== #
    def update_domain(self, domain_name, aggregated_summary):
        """Write aggregated BM + announcement to a DataDomain entity in Atlan.

        Finds the domain GUID from the domain map, then writes BM and
        announcement just like individual assets.
        """
        # Find domain GUID by name
        domain_guid = None
        domain_qn = None
        for guid, info in self._domain_guid_map.items():
            if info["name"] == domain_name:
                domain_guid = guid
                domain_qn = info.get("qualifiedName", "")
                break

        if not domain_guid:
            self.logger.debug(f"Domain '{domain_name}' not found in Atlan — skipping domain-level metadata.")
            return False

        if not domain_qn:
            self.logger.debug(f"Domain '{domain_name}' has no qualifiedName — skipping.")
            return False

        self.logger.info(f"Writing governance metadata to domain '{domain_name}' ({domain_guid})")

        # Write BM using the same logic as update_asset
        ok = self.update_asset(
            domain_guid, aggregated_summary,
            type_name="DataDomain",
            asset_name=domain_name,
            qualified_name=domain_qn,
        )

        return ok
