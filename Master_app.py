#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Inventory baseline + sales_total updater for Shopify inventory_levels/update.

- Verifies HMAC.
- Baseline stored per (shop, inventory_item_id, location_id) in STATE file.
- On webhook:
    Δ = new_available - prev_available (if prev exists)
    if Δ < 0: sales_total += -Δ  (on rudradhan.com only)
    then update baseline to new_available.
- Baseline seeding:
    * Auto at boot with INIT_BASELINE_ON_BOOT=1 (optional)
    * Manual endpoint: GET /admin/init-baseline?key=ADMIN_BASELINE_KEY&shop=com|us
"""

import os
import json
import hmac
import base64
import hashlib
import logging
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, Optional, Tuple

import requests
from flask import Flask, request, abort, jsonify

# ---------------- Config helpers ----------------

def env(name: str, default: str = "") -> str:
    v = os.getenv(name)
    return v if v is not None and str(v).strip() != "" else default

def ensure_parent_writable(file_path: str) -> str:
    p = Path(file_path)
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        return str(p)
    except Exception:
        pass
    local = Path.cwd() / "data" / p.name
    try:
        local.parent.mkdir(parents=True, exist_ok=True)
        return str(local)
    except Exception:
        pass
    return str(Path(tempfile.gettempdir()) / p.name)

CONFIG: Dict[str, Any] = {
    # Primary (.com): the ONLY shop we write metafields to
    "COM_SHOP_DOMAIN":    env("COM_SHOP_DOMAIN"),   # e.g. rudradhan.myshopify.com
    "COM_ADMIN_TOKEN":    env("COM_ADMIN_TOKEN"),
    "COM_WEBHOOK_SECRET": env("COM_WEBHOOK_SECRET"),

    # Secondary (.us): used for verifying HMAC & lookups only (no writes)
    "US_SHOP_DOMAIN":     env("US_SHOP_DOMAIN"),
    "US_ADMIN_TOKEN":     env("US_ADMIN_TOKEN"),
    "US_WEBHOOK_SECRET":  env("US_WEBHOOK_SECRET"),

    # State/log
    "STATE_PATH": ensure_parent_writable(env("STATE_PATH", "/data/state.json")),
    "LOG_LEVEL": env("LOG_LEVEL", "INFO"),

    # Baseline init
    "INIT_BASELINE_ON_BOOT": env("INIT_BASELINE_ON_BOOT", "0"),
    "ADMIN_BASELINE_KEY": env("ADMIN_BASELINE_KEY", ""),  # for manual /admin/init-baseline

    # Network
    "HTTP_TIMEOUT": float(env("HTTP_TIMEOUT", "12.0")),
}

# ---------------- Logging ----------------

logger = logging.getLogger("inv")
if not logger.handlers:
    h = logging.StreamHandler()
    h.setFormatter(logging.Formatter("[%(asctime)s IST] %(message)s", datefmt="%Y-%m-%d %H:%M:%S"))
    logger.addHandler(h)
    logger.setLevel(getattr(logging, (CONFIG["LOG_LEVEL"] or "INFO").upper(), logging.INFO))
    logger.propagate = False
def log(msg: str): logger.info(msg)
def warn(msg: str): logger.warning(msg)

# ---------------- Flask ----------------

app = Flask(__name__)

@app.after_request
def cors(resp):
    resp.headers["Access-Control-Allow-Origin"]  = "*"
    resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type"
    return resp

@app.before_request
def trace():
    origin = request.headers.get("Origin") or request.headers.get("Referer") or "-"
    ua = (request.headers.get("User-Agent") or "")[:100]
    log(f"REQ {request.method} {request.path} origin={origin} ua={ua}")

# ---------------- State file ----------------

def load_state() -> Dict[str, Any]:
    p = Path(CONFIG["STATE_PATH"])
    if not p.exists():
        return {"levels_by_loc": {}}  # key: f"{shop}|{inv_item_id}:{location_id}" -> available
    try:
        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)
        data.setdefault("levels_by_loc", {})
        return data
    except Exception as e:
        warn(f"Failed to read state: {e}")
        return {"levels_by_loc": {}}

def save_state(state: Dict[str, Any]) -> None:
    try:
        tmp = CONFIG["STATE_PATH"] + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(state, f, ensure_ascii=False, indent=2)
        os.replace(tmp, CONFIG["STATE_PATH"])
    except Exception as e:
        warn(f"Failed to write state: {e}")

STATE = load_state()

# ---------------- Shopify helpers ----------------

def verify_hmac(raw: bytes, provided_b64: str, secret: str) -> bool:
    digest = hmac.new(secret.encode(), raw, hashlib.sha256).digest()
    expected = base64.b64encode(digest).decode()
    return hmac.compare_digest(provided_b64 or "", expected)

def shop_headers(shop: str) -> dict:
    token = CONFIG["COM_ADMIN_TOKEN"] if shop == "com" else CONFIG["US_ADMIN_TOKEN"]
    return {
        "X-Shopify-Access-Token": token,
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

def shop_domain(shop: str) -> str:
    return CONFIG["COM_SHOP_DOMAIN"] if shop == "com" else CONFIG["US_SHOP_DOMAIN"]

def gid(kind: str, num_id: int) -> str:
    return f"gid://shopify/{kind}/{int(num_id)}"

def gid_num(g: Optional[str]) -> int:
    try: return int((g or "").rsplit("/", 1)[-1])
    except: return 0

def graphql(shop: str, query: str, variables: dict) -> dict:
    r = requests.post(
        f"https://{shop_domain(shop)}/admin/api/2024-10/graphql.json",
        headers=shop_headers(shop),
        json={"query": query, "variables": variables},
        timeout=CONFIG["HTTP_TIMEOUT"],
    )
    if r.status_code != 200:
        raise RuntimeError(f"GraphQL HTTP {r.status_code}: {r.text[:300]}")
    data = r.json()
    if data.get("errors"):
        raise RuntimeError(f"GraphQL errors: {data['errors']}")
    return data.get("data", {})

# ----- Lookups -----

def lookup_title_sku_by_inventory_item(shop: str, inventory_item_id: int) -> Tuple[str, str, int]:
    """
    Returns (product_title, sku, product_id)
    """
    q = """
    query($id: ID!){
      inventoryItem(id:$id){
        sku
        variant{
          id
          sku
          product{ id title }
        }
      }
    }"""
    try:
        data = graphql(shop, q, {"id": f"gid://shopify/InventoryItem/{int(inventory_item_id)}"})
        inv = data.get("inventoryItem") or {}
        var = inv.get("variant") or {}
        prod = var.get("product") or {}
        title = (prod.get("title") or "").strip()
        sku = (var.get("sku") or inv.get("sku") or "").strip()
        pid = gid_num(prod.get("id"))
        return title, sku, pid
    except Exception as e:
        warn(f"lookup_title_sku_by_inventory_item failed on {shop} for {inventory_item_id}: {e}")
        return "", "", 0

# ----- Metafields (WRITE ONLY ON .com) -----

def set_product_metafields_primary(product_id: int, fields: dict):
    """
    fields: { (ns,key,type): value_string }
    """
    if not product_id:
        return
    metas = []
    for (ns, key, mtype), value in fields.items():
        metas.append({
            "ownerId": gid("Product", product_id),
            "namespace": ns,
            "key": key,
            "type": mtype,
            "value": str(value),
        })
    m = """
    mutation($metafields:[MetafieldsSetInput!]!){
      metafieldsSet(metafields:$metafields){ userErrors{ field message } }
    }"""
    try:
        graphql("com", m, {"metafields": metas})
    except Exception as e:
        warn(f"metafieldsSet (.com) failed: {e}")

def bump_sales_total_primary(product_id: int, units: int):
    if units <= 0 or not product_id:
        return
    # Read current fields
    q = """
    query($id: ID!){
      product(id:$id){
        sales_total: metafield(namespace:"custom", key:"sales_total"){ value type }
        sales_dates: metafield(namespace:"custom", key:"sales_dates"){ value type }
      }
    }"""
    cur_total, cur_dates = 0, []
    try:
        data = graphql("com", q, {"id": gid("Product", product_id)})
        p = data.get("product") or {}
        st = p.get("sales_total"); sd = p.get("sales_dates")
        if st and st.get("type") == "number_integer" and st.get("value"):
            cur_total = int(st["value"])
        if sd and sd.get("type") == "list.date" and sd.get("value"):
            try:
                cur_dates = json.loads(sd["value"])
            except Exception:
                cur_dates = []
    except Exception as e:
        warn(f"read sales metafields failed: {e}")

    new_total = cur_total + int(units)
    today_ist = (datetime.utcnow() + timedelta(hours=5, minutes=30)).strftime("%Y-%m-%d")
    if today_ist not in cur_dates:
        cur_dates.append(today_ist)

    set_product_metafields_primary(product_id, {
        ("custom", "sales_total", "number_integer"): str(new_total),
        ("custom", "sales_dates", "list.date"): json.dumps(cur_dates),
    })
    log(f"[.com] SALES_TOTAL +={units} (product_id={product_id}) → {new_total}")

# ---------------- Baseline initialization ----------------

def seed_baseline_for_shop(shop: str) -> int:
    """
    Scans all inventory items for the given shop and seeds STATE["levels_by_loc"] with
    available per (inventory_item_id, location_id).

    Returns: number of (item,location) entries recorded.
    """
    if shop == "com" and not (CONFIG["COM_SHOP_DOMAIN"] and CONFIG["COM_ADMIN_TOKEN"]):
        warn("COM credentials missing; cannot seed baseline.")
        return 0
    if shop == "us" and not (CONFIG["US_SHOP_DOMAIN"] and CONFIG["US_ADMIN_TOKEN"]):
        warn("US credentials missing; cannot seed baseline.")
        return 0

    total = 0
    cursor = None
    while True:
        q = """
        query($cursor: String){
          inventoryItems(first: 200, after: $cursor){
            edges{
              cursor
              node{
                id
                inventoryLevels(first: 25){
                  nodes{
                    location { id }
                    quantities(names: ["available"]){
                      name
                      quantity
                    }
                  }
                }
              }
            }
            pageInfo{ hasNextPage endCursor }
          }
        }"""

        data = graphql(shop, q, {"cursor": cursor})
        items = ((data.get("inventoryItems") or {}).get("edges") or [])
        for e in items:
            node = e.get("node") or {}
            inv_item_id = gid_num(node.get("id"))
            levels = ((node.get("inventoryLevels") or {}).get("nodes") or [])
            for lv in levels:
                loc_id = gid_num((lv.get("location") or {}).get("id"))
                qtys = (lv.get("quantities") or [])
                available = 0
                for qn in qtys:
                    if (qn.get("name") or "").lower() == "available":
                        available = int(qn.get("quantity") or 0)
                        break
                key = f"{shop}|{inv_item_id}:{loc_id}"
                STATE["levels_by_loc"][key] = available
                total += 1
        page = (data.get("inventoryItems") or {}).get("pageInfo") or {}
        if not page.get("hasNextPage"):
            break
        cursor = page.get("endCursor")
    save_state(STATE)
    log(f"[{shop}] Baseline seeded entries={total}")
    return total

# ---------------- Webhook handling ----------------

def handle_inventory_webhook(shop: str, payload: dict):
    inv_item_id = int(payload.get("inventory_item_id"))
    loc_id     = int(payload.get("location_id") or 0)
    new_avail  = int(payload.get("available"))

    # Resolve a pretty title + product id for writing (on .com)
    title, sku, product_id = lookup_title_sku_by_inventory_item(shop, inv_item_id)

    key = f"{shop}|{inv_item_id}:{loc_id}"
    prev = STATE["levels_by_loc"].get(key)

    log(f"[.{shop}] AVAILABILITY: {title or '(unknown title)'}"
        f"{(' | SKU: '+sku) if sku else ''} | prev: {prev if prev is not None else '—'} → new: {new_avail} "
        f"(inv_item_id={inv_item_id}, location_id={loc_id})")

    # Compute delta if we have a baseline
    if prev is not None:
        delta = new_avail - int(prev)
        if delta < 0:
            # Only write sales_total on .com (primary) for this product
            # If webhook is from .us we still write on .com for the mapped product_id
            # We already resolved product_id from the SENDING shop's inventory item.
            # On cross-shop, product_id will be from .us; we still increment sales on .com,
            # because product_id refers to the sending shop. So we need the .com product id.
            # Simplest approach: if shop == 'com' we already have correct product_id.
            # If shop == 'us', we need to find the corresponding .com product by SKU.
            pid_to_write = product_id
            if shop == "us" and sku:
                # Map SKU -> .com product
                q = """
                query($q:String!){
                  productVariants(first:10, query:$q){
                    nodes{ product{ id } sku }
                  }
                }"""
                try:
                    data = graphql("com", q, {"q": f"sku:{sku}"})
                    nodes = ((data.get("productVariants") or {}).get("nodes") or [])
                    for n in nodes:
                        if (n.get("sku") or "").strip() == sku:
                            pid_to_write = gid_num(((n.get("product") or {}).get("id")))
                            break
                except Exception as e:
                    warn(f"map SKU to .com failed: {e}")

            if pid_to_write:
                bump_sales_total_primary(pid_to_write, -delta)

    # Update baseline
    STATE["levels_by_loc"][key] = new_avail
    save_state(STATE)

# ---------------- Routes ----------------
@app.route("/debug/ping", methods=["GET"])
def debug_ping():
    return jsonify({
        "ok": True,
        "time_utc": datetime.utcnow().isoformat() + "Z",
        "expect_webhook": "/webhooks/shopify"
    }), 200


@app.route("/", methods=["GET", "HEAD"])
def root_ok():
    return "OK", 200

@app.route("/healthz", methods=["GET"])
def healthz():
    return jsonify({"ok": True}), 200
@app.route("/track/product", methods=["POST", "OPTIONS"])
def track_product():
    if request.method == "OPTIONS":
        return "", 200  # preflight OK
    if request.args.get("key") != CONFIG["PIXEL_SHARED_SECRET"]:
        abort(401)
    ...
@app.route("/track/atc", methods=["POST", "OPTIONS"])
def track_atc():
    if request.method == "OPTIONS":
        return "", 200
    if request.args.get("key") != CONFIG["PIXEL_SHARED_SECRET"]:
        abort(401)
    ...

@app.route("/admin/init-baseline", methods=["GET"])
def init_baseline_route():
    key = request.args.get("key", "")
    if not CONFIG["ADMIN_BASELINE_KEY"] or key != CONFIG["ADMIN_BASELINE_KEY"]:
        return jsonify({"ok": False, "error": "unauthorized"}), 401
    shop = (request.args.get("shop") or "com").strip().lower()
    if shop not in ("com", "us"):
        return jsonify({"ok": False, "error": "shop must be com|us"}), 400
    count = seed_baseline_for_shop(shop)
    return jsonify({"ok": True, "shop": shop, "entries": count}), 200

import os
import json

@app.route("/webhooks/shopify", methods=["POST"])
def webhook_shopify():
    raw = request.get_data(cache=True)
    topic = request.headers.get("X-Shopify-Topic", "")
    shop_domain = (request.headers.get("X-Shopify-Shop-Domain") or "").lower().strip()
    provided_hmac = request.headers.get("X-Shopify-Hmac-Sha256", "")
    trig_at = request.headers.get("X-Shopify-Triggered-At", "")
    wh_id = request.headers.get("X-Shopify-Webhook-Id", "")

    # Decide shop + secret (same as before)
    if CONFIG["COM_SHOP_DOMAIN"] and shop_domain.endswith(CONFIG["COM_SHOP_DOMAIN"].lower()):
        shop, secret = "com", CONFIG["COM_WEBHOOK_SECRET"]
    elif CONFIG["US_SHOP_DOMAIN"] and shop_domain.endswith(CONFIG["US_SHOP_DOMAIN"].lower()):
        shop, secret = "us", CONFIG["US_WEBHOOK_SECRET"]
    else:
        shop = "com" if ".com" in shop_domain else "us"
        secret = CONFIG["COM_WEBHOOK_SECRET"] if shop == "com" else CONFIG["US_WEBHOOK_SECRET"]

    # LOUD: incoming webhook line
    log(f"WH IN topic={topic} shop={shop} shop_domain={shop_domain or '—'} "
        f"hmac={'yes' if provided_hmac else 'no'} len={len(raw)} trig_at={trig_at or '—'} id={wh_id or '—'}")

    # Optional: raw body (toggle with env)
    if os.getenv("DEBUG_LOG_BODY", "0") == "1":
        try:
            sample = raw.decode("utf-8", "ignore")
            if len(sample) > 2000:
                sample = sample[:2000] + " …(truncated)…"
            log(f"WH BODY: {sample}")
        except Exception as e:
            log(f"[WARN] Could not decode raw body: {e}")

    # HMAC check
    if not secret:
        log("[ERR] No webhook secret configured for this shop; rejecting")
        abort(401)
    if not verify_hmac(raw, provided_hmac, secret):
        log("[ERR] HMAC verification failed; rejecting")
        abort(401)

    # Parse JSON (and log key fields)
    try:
        payload = request.get_json(force=True, silent=False) or {}
    except Exception as e:
        log(f"[ERR] JSON parse failed: {e}")
        abort(400, description="Invalid JSON payload")

    inv_item_id = payload.get("inventory_item_id")
    location_id = payload.get("location_id")
    available   = payload.get("available")

    log(f"WH OK topic={topic} inv_item_id={inv_item_id} location_id={location_id} available={available}")

    # Only handle the topic we care about
    if topic != "inventory_levels/update":
        log(f"WH IGNORE topic={topic}")
        return "", 200

    # Hand off to your existing handler
    handle_inventory_webhook(shop, payload)
    return "", 200


# ---------------- Boot-time baseline (optional) ----------------

def maybe_seed_on_boot():
    if CONFIG["INIT_BASELINE_ON_BOOT"] != "1":
        return
    # Seed .com; seed .us only if creds are present (no writes will be done there)
    try:
        seed_baseline_for_shop("com")
    except Exception as e:
        warn(f"Boot baseline (.com) failed: {e}")
    try:
        if CONFIG["US_SHOP_DOMAIN"] and CONFIG["US_ADMIN_TOKEN"]:
            seed_baseline_for_shop("us")
    except Exception as e:
        warn(f"Boot baseline (.us) failed: {e}")

# ---------------- Entrypoint ----------------

maybe_seed_on_boot()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "10000")))
