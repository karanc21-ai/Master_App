#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os, sys, json, hmac, time, base64, sqlite3, hashlib, logging
from pathlib import Path
from typing import Optional, Tuple
from datetime import datetime, timedelta

import requests
from flask import Flask, request, abort, jsonify

# =========================
# Config
# =========================

def env(name: str, default: str = "") -> str:
    v = os.getenv(name)
    return v if v is not None and str(v).strip() != "" else default

CONFIG = {
    # Primary (.com)
    "COM_SHOP_DOMAIN":    env("COM_SHOP_DOMAIN"),   # e.g. rudradhan.myshopify.com
    "COM_ADMIN_TOKEN":    env("COM_ADMIN_TOKEN"),
    "COM_WEBHOOK_SECRET": env("COM_WEBHOOK_SECRET"),

    # Secondary (.us) — used ONLY to verify HMAC and resolve SKU/title. No writes.
    "US_SHOP_DOMAIN":     env("US_SHOP_DOMAIN"),
    "US_ADMIN_TOKEN":     env("US_ADMIN_TOKEN"),
    "US_WEBHOOK_SECRET":  env("US_WEBHOOK_SECRET"),

    # Pixel shared secret (matches ?key=SECRET in your pixel)
    "PIXEL_SHARED_SECRET": env("PIXEL_SHARED_SECRET"),

    # Metafields & toggles — writes are .com-only
    "BADGES_READY":     env("BADGES_READY", "Ready To Ship"),
    "DELIVERY_READY":   env("DELIVERY_READY", "2-5 Days Across India"),
    "DELIVERY_OOS":     env("DELIVERY_OOS", "12-15 Days Across India"),
    "WRITE_BADGES_COM": env("WRITE_BADGES_COM", "1"),

    # Optional sqlite (for pixel dedupe + sku cache). Falls back to /tmp.
    "DB_PATH": env("DB_PATH", "/data/app.db"),

    # Network timeouts
    "HTTP_TIMEOUT": float(env("HTTP_TIMEOUT", "10.0")),
}

def ensure_db_path(p: str) -> str:
    try:
        Path(p).parent.mkdir(parents=True, exist_ok=True)
        return p
    except Exception:
        tmp = "/tmp/app.db"
        Path(tmp).parent.mkdir(parents=True, exist_ok=True)
        return tmp

CONFIG["DB_PATH"] = ensure_db_path(CONFIG["DB_PATH"])

# =========================
# Logger (unbuffered)
# =========================

os.environ.setdefault("PYTHONUNBUFFERED", "1")
logger = logging.getLogger("master_app")
if not logger.handlers:
    h = logging.StreamHandler(sys.stdout)
    h.setFormatter(logging.Formatter("[%(asctime)s IST] %(message)s", datefmt="%Y-%m-%d %H:%M:%S"))
    logger.addHandler(h)
    logger.setLevel(logging.INFO)
    logger.propagate = False

def log_line(msg: str): logger.info(msg)

# =========================
# App + CORS + request trace
# =========================

app = Flask(__name__)

@app.after_request
def add_cors_headers(resp):
    resp.headers["Access-Control-Allow-Origin"]  = "*"
    resp.headers["Access-Control-Allow-Methods"] = "POST, OPTIONS"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type, X-Pixel-Token"
    return resp

@app.before_request
def _trace():
    origin = request.headers.get("Origin") or request.headers.get("Referer") or "-"
    ua = (request.headers.get("User-Agent") or "")[:100]
    log_line(f"REQ {request.method} {request.path} origin={origin} ua={ua}")

# =========================
# DB (for pixel dedupe + SKU cache only)
# =========================

def db() -> sqlite3.Connection:
    conn = sqlite3.connect(CONFIG["DB_PATH"], timeout=10)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with db() as conn:
        conn.executescript("""
            PRAGMA journal_mode = WAL;

            CREATE TABLE IF NOT EXISTS pixel_seen (
              id TEXT PRIMARY KEY,
              seen_at INTEGER
            );

            CREATE TABLE IF NOT EXISTS sku_map (
              shop TEXT NOT NULL,
              product_id INTEGER NOT NULL,
              sku TEXT NOT NULL,
              PRIMARY KEY (shop, product_id)
            );
        """)
init_db()

# =========================
# Shopify helpers
# =========================

def verify_shopify_hmac(raw: bytes, provided_b64: str, secret: str) -> bool:
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

def gid_num(gid_str: Optional[str]) -> int:
    try: return int((gid_str or "").rsplit("/", 1)[-1])
    except: return 0

def graphql(shop: str, query: str, variables: dict) -> dict:
    r = requests.post(
        f"https://{shop_domain(shop)}/admin/api/2024-10/graphql.json",
        headers=shop_headers(shop),
        json={"query": query, "variables": variables},
        timeout=CONFIG["HTTP_TIMEOUT"],
    )
    if r.status_code != 200:
        raise RuntimeError(f"GraphQL HTTP {r.status_code}: {r.text[:400]}")
    data = r.json()
    if "errors" in data and data["errors"]:
        raise RuntimeError(f"GraphQL errors: {data['errors']}")
    return data.get("data", {})

# --- lookups ---

def get_product_title_by_product_id(shop: str, product_id: int) -> str:
    if not product_id: return ""
    q = """query($id: ID!){ product(id:$id){ title } }"""
    try:
        data = graphql(shop, q, {"id": gid("Product", product_id)})
        return ((data.get("product") or {}).get("title") or "").strip()
    except Exception as e:
        print(f"[WARN] title lookup failed on {shop} product_id={product_id}: {e}")
        return ""

def get_variant_product_info_from_inventory(shop: str, inventory_item_id: int) -> Tuple[Optional[str], Optional[int], str]:
    """
    Returns (sku, product_id, product_title) via inventoryItem → variant → product (exact mapping).
    """
    q = """
    query($id: ID!) {
      inventoryItem(id: $id) {
        sku
        variant { id sku product { id title } }
      }
    }"""
    try:
        data = graphql(shop, q, {"id": gid("InventoryItem", inventory_item_id)})
        inv = data.get("inventoryItem") or {}
        var = inv.get("variant") or {}
        prod = var.get("product") or {}
        sku = (var.get("sku") or inv.get("sku") or "").strip()
        product_id = gid_num(prod.get("id"))
        title = (prod.get("title") or "").strip()
        return sku or None, product_id or None, title
    except Exception as e:
        print(f"[WARN] inventory→variant→product info failed on {shop} inventory_item_id={inventory_item_id}: {e}")
        return None, None, ""

def get_sku_from_product_id(shop: str, product_id: int) -> Optional[str]:
    if not product_id: return None
    with db() as conn:
        row = conn.execute("SELECT sku FROM sku_map WHERE shop=? AND product_id=?", (shop, product_id)).fetchone()
        if row: return (row["sku"] or "").strip() or None
    q = """query($id: ID!){ product(id:$id){ variants(first:1){ nodes{ sku } } } }"""
    try:
        data = graphql(shop, q, {"id": gid("Product", product_id)})
        nodes = ((data.get("product") or {}).get("variants") or {}).get("nodes") or []
        if nodes:
            sku = (nodes[0].get("sku") or "").strip()
            if sku:
                with db() as conn:
                    conn.execute("INSERT OR REPLACE INTO sku_map(shop,product_id,sku) VALUES (?,?,?)", (shop, product_id, sku))
                return sku
    except Exception as e:
        print(f"[WARN] sku_from_product_id failed on {shop} product_id={product_id}: {e}")
    return None

def get_primary_product_by_sku(sku: str) -> Tuple[Optional[int], Optional[int]]:
    if not sku: return None, None
    q = """
    query($q: String!) {
      productVariants(first:10, query:$q) {
        nodes { id sku product { id } }
      }
    }"""
    try:
        data = graphql("com", q, {"q": f"sku:{sku}"})
        nodes = (data.get("productVariants") or {}).get("nodes") or []
        for n in nodes:
            if (n.get("sku") or "").strip() == sku.strip():
                pid = gid_num((n.get("product") or {}).get("id"))
                vid = gid_num(n.get("id"))
                if pid: return pid, vid or None
    except Exception as e:
        print(f"[WARN] primary_by_sku failed for sku={sku}: {e}")
    return None, None

# ---------- Metafield writers (ONLY .com) ----------

def set_product_metafields_primary(product_id: int, fields: dict):
    """
    fields: { (namespace, key, type): value_string } — writes on .com only
    """
    if not product_id: return
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
    mutation($metafields: [MetafieldsSetInput!]!) {
      metafieldsSet(metafields:$metafields) { userErrors { field message } }
    }"""
    try:
        graphql("com", m, {"metafields": metas})
    except Exception as e:
        print(f"[WARN] metafieldsSet primary failed: {e}")

def bump_primary_sales(sku: str, delta_sales: int):
    if delta_sales <= 0 or not sku: return
    pid, _ = get_primary_product_by_sku(sku)
    if not pid: return
    # Read current totals (sales_total & sales_dates)
    q = """
    query($id: ID!) {
      product(id:$id) {
        sales_total: metafield(namespace:"custom", key:"sales_total"){ value type }
        sales_dates: metafield(namespace:"custom", key:"sales_dates"){ value type }
      }
    }"""
    cur_total, cur_dates = 0, []
    try:
        data = graphql("com", q, {"id": gid("Product", pid)})
        p = data.get("product") or {}
        st = p.get("sales_total"); sd = p.get("sales_dates")
        if st and st.get("type") == "number_integer" and st.get("value"): cur_total = int(st["value"])
        if sd and sd.get("type") == "list.date" and sd.get("value"):
            try: cur_dates = json.loads(sd["value"])
            except Exception: cur_dates = []
    except Exception as e:
        print(f"[WARN] read sales metafields failed: {e}")

    new_total = cur_total + int(delta_sales)
    today = (datetime.utcnow() + timedelta(hours=5, minutes=30)).strftime("%Y-%m-%d")
    if today not in cur_dates: cur_dates.append(today)

    set_product_metafields_primary(pid, {
        ("custom", "sales_total", "number_integer"): str(new_total),
        ("custom", "sales_dates", "list.date"): json.dumps(cur_dates),
    })
    log_line(f"[.com] SALES_TOTAL +={int(delta_sales)} (SKU {sku}) → now {new_total} (product_id={pid})")

def adjust_badges_and_delivery(shop: str, product_id: int, available_now: int):
    # Only write on .com — never on .us
    if shop != "com": return
    if CONFIG["WRITE_BADGES_COM"] != "1": return
    if not product_id: return
    ns = "custom"
    if available_now <= 0:
        fields = {
            (ns, "badges", "single_line_text_field"): "",
            (ns, "delivery_time", "single_line_text_field"): CONFIG["DELIVERY_OOS"],
        }
    else:
        fields = {
            (ns, "badges", "single_line_text_field"): CONFIG["BADGES_READY"],
            (ns, "delivery_time", "single_line_text_field"): CONFIG["DELIVERY_READY"],
        }
    set_product_metafields_primary(product_id, fields)

# =========================
# Pixel handlers (unchanged contract)
# =========================

def bump_primary_views_or_atc_from_pixel(shop_host: str, product_id: int, kind: str, qty: int):
    shop = "us" if ("rudradhan.us" in (shop_host or "")) else "com"
    sku = get_sku_from_product_id(shop, product_id)
    title_src = get_product_title_by_product_id(shop, product_id)
    show_shop = ".us" if shop == "us" else ".com"

    pid_primary, _ = get_primary_product_by_sku(sku) if sku else (None, None)
    field_key = "views_total" if kind == "product" else "added_to_cart_total"

    if pid_primary:
        q = f"""query($id: ID!){{ product(id:$id){{ title mf:metafield(namespace:"custom",key:"{field_key}"){{ value type }} }} }}"""
        try:
            data = graphql("com", q, {"id": gid("Product", pid_primary)})
            p = data.get("product") or {}
            primary_title = (p.get("title") or "").strip()
            mf = p.get("mf")
            cur = 0
            if mf and mf.get("type") == "number_integer" and mf.get("value"): cur = int(mf["value"])
            new_val = cur + int(max(1, qty))
            set_product_metafields_primary(pid_primary, {("custom", field_key, "number_integer"): str(new_val)})
            if kind == "product":
                log_line(f"[{show_shop}] VIEWED: {primary_title or title_src or '(unknown title)'} (SKU: {sku or '—'}) → views_total={new_val}")
            else:
                log_line(f"[{show_shop}] ADDED TO CART ×{max(1, qty)}: {primary_title or title_src or '(unknown title)'} (SKU: {sku or '—'}) → added_to_cart_total={new_val}")
        except Exception as e:
            print(f"[WARN] pixel bump failed: {e}")
    else:
        action = "VIEWED" if kind == "product" else f"ADDED TO CART ×{max(1, qty)}"
        log_line(f"[{show_shop}] {action}: {title_src or '(unknown title)'} (ProductID={product_id}{' | SKU: '+sku if sku else ''})")

@app.route("/track/product", methods=["POST"])
def track_product():
    if request.args.get("key") != CONFIG["PIXEL_SHARED_SECRET"]: abort(401)
    body = request.get_json(force=True, silent=True) or {}
    product_id = int(body.get("productId") or 0)
    shop_host = (body.get("shop") or "").lower()
    if product_id <= 0 or not shop_host: return "", 200
    ev_id = body.get("event_id") or f"{shop_host}:product:{product_id}:{int(body.get('ts') or 0)}"
    with db() as conn:
        if conn.execute("SELECT 1 FROM pixel_seen WHERE id=?", (ev_id,)).fetchone(): return "", 200
        conn.execute("INSERT OR IGNORE INTO pixel_seen(id, seen_at) VALUES (?,?)", (ev_id, int(time.time())))
    bump_primary_views_or_atc_from_pixel(shop_host, product_id, "product", 1)
    return "", 200

@app.route("/track/atc", methods=["POST"])
def track_atc():
    if request.args.get("key") != CONFIG["PIXEL_SHARED_SECRET"]: abort(401)
    body = request.get_json(force=True, silent=True) or {}
    product_id = int(body.get("productId") or 0)
    qty = int(body.get("qty") or 1)
    shop_host = (body.get("shop") or "").lower()
    if product_id <= 0 or not shop_host: return "", 200
    ev_id = body.get("event_id") or f"{shop_host}:atc:{product_id}:{int(body.get('ts') or 0)}"
    with db() as conn:
        if conn.execute("SELECT 1 FROM pixel_seen WHERE id=?", (ev_id,)).fetchone(): return "", 200
        conn.execute("INSERT OR IGNORE INTO pixel_seen(id, seen_at) VALUES (?,?)", (ev_id, int(time.time())))
    bump_primary_views_or_atc_from_pixel(shop_host, product_id, "atc", max(1, qty))
    return "", 200

# =========================
# Inventory webhooks
# =========================

def handle_inventory_update(shop: str, payload: dict):
    """
    NO BASELINE.
    - read available (for badges) and available_adjustment (delta)
    - resolve sku/title from inventory_item_id using the SENDING shop
    - if delta < 0: bump sales_total on PRIMARY (.com) by -delta
    - never write metafields on .us directly
    """
    inv_id = int(payload.get("inventory_item_id"))
    available = int(payload.get("available"))
    loc_id = int(payload.get("location_id") or 0)
    # May be absent; we do NOT infer without baseline
    delta = int(payload.get("available_adjustment") or 0)

    sku, product_id, product_title = get_variant_product_info_from_inventory(shop, inv_id)

    log_line(f"[.{shop}] AVAILABILITY: {product_title or '(unknown title)'} (SKU: {sku or '—'}) "
             f"new_available: {available} "
             f"(Δ={delta}, inv_item_id={inv_id}, location_id={loc_id})")

    # Update badges/delivery only on .com (based on current availability)
    adjust_badges_and_delivery("com" if shop == "com" else "us", product_id or 0, available)

    # Sales: only when delta is negative, and we always write on the PRIMARY using SKU
    if delta < 0 and sku:
        bump_primary_sales(sku, -delta)
    elif delta == 0:
        log_line("[INFO] No available_adjustment in payload (or zero). Skipping sales_total bump (per no-baseline rule).")

@app.route("/webhooks/shopify", methods=["POST"])
def webhook_shopify():
    raw = request.get_data(cache=True)
    topic = request.headers.get("X-Shopify-Topic", "")
    shop_domain_hdr = (request.headers.get("X-Shopify-Shop-Domain") or "").lower().strip()

    # Select secret & shop by domain
    if CONFIG["COM_SHOP_DOMAIN"] and shop_domain_hdr.endswith(CONFIG["COM_SHOP_DOMAIN"].lower()):
        shop = "com"; secret = CONFIG["COM_WEBHOOK_SECRET"]
    elif CONFIG["US_SHOP_DOMAIN"] and shop_domain_hdr.endswith(CONFIG["US_SHOP_DOMAIN"].lower()):
        shop = "us"; secret = CONFIG["US_WEBHOOK_SECRET"]
    else:
        # Fallback guess
        shop = "com" if ".com" in shop_domain_hdr else "us"
        secret = CONFIG["COM_WEBHOOK_SECRET"] if shop == "com" else CONFIG["US_WEBHOOK_SECRET"]

    if not verify_shopify_hmac(raw, request.headers.get("X-Shopify-Hmac-Sha256", ""), secret):
        log_line(f"WH HMAC FAIL ({shop})")
        abort(401)

    if topic != "inventory_levels/update":
        log_line(f"WH ignored topic={topic}")
        return "", 200

    payload = request.get_json(force=True, silent=False) or {}
    handle_inventory_update(shop, payload)
    return "", 200

# (Optional) Per-shop endpoints if you want to wire them separately
@app.route("/webhooks/com/inventory", methods=["POST"])
def wh_com():
    raw = request.get_data(cache=True)
    if not verify_shopify_hmac(raw, request.headers.get("X-Shopify-Hmac-Sha256", ""), CONFIG["COM_WEBHOOK_SECRET"]):
        abort(401)
    payload = request.get_json(force=True, silent=False) or {}
    handle_inventory_update("com", payload)
    return "", 200

@app.route("/webhooks/us/inventory", methods=["POST"])
def wh_us():
    raw = request.get_data(cache=True)
    if not verify_shopify_hmac(raw, request.headers.get("X-Shopify-Hmac-Sha256", ""), CONFIG["US_WEBHOOK_SECRET"]):
        abort(401)
    payload = request.get_json(force=True, silent=False) or {}
    handle_inventory_update("us", payload)
    return "", 200

# =========================
# Health + root
# =========================

@app.route("/", methods=["GET", "HEAD"])
def root_ok(): return "OK", 200

@app.route("/healthz", methods=["GET"])
def healthz(): return jsonify({"ok": True}), 200

# =========================
# Entrypoint
# =========================

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "10000")))
