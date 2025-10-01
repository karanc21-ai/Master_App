#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import json
import hmac
import time
import base64
import sqlite3
import hashlib
from pathlib import Path
from typing import Optional, Tuple

import requests
from flask import Flask, request, abort, jsonify
from datetime import datetime, timedelta

# =========================
# Config & app bootstrap
# =========================

def env(name: str, default: str = "") -> str:
    v = os.getenv(name)
    return v if v is not None and str(v).strip() != "" else default

CONFIG = {
    # Primary (.com)
    "COM_SHOP_DOMAIN": env("COM_SHOP_DOMAIN"),            # e.g. rudradhan.myshopify.com
    "COM_ADMIN_TOKEN": env("COM_ADMIN_TOKEN"),
    "COM_WEBHOOK_SECRET": env("COM_WEBHOOK_SECRET"),

    # Secondary (.us)
    "US_SHOP_DOMAIN": env("US_SHOP_DOMAIN"),
    "US_ADMIN_TOKEN": env("US_ADMIN_TOKEN"),
    "US_WEBHOOK_SECRET": env("US_WEBHOOK_SECRET"),

    # Pixel shared secret (matches ?key=SECRET in your working pixel)
    "PIXEL_SHARED_SECRET": env("PIXEL_SHARED_SECRET"),

    # Metafield strings & toggles
    "BADGES_READY": env("BADGES_READY", "Ready To Ship"),
    "DELIVERY_READY": env("DELIVERY_READY", "2-5 Days Across India"),
    "DELIVERY_OOS": env("DELIVERY_OOS", "12-15 Days Across India"),
    "WRITE_BADGES_COM": env("WRITE_BADGES_COM", "1"),
    "WRITE_BADGES_US": env("WRITE_BADGES_US", "1"),

    # DB path (attach a Render disk at /data for persistence; will fallback to /tmp)
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

app = Flask(__name__)

# CORS for pixel endpoints and future clients
@app.after_request
def add_cors_headers(resp):
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Methods"] = "POST, OPTIONS"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type, X-Pixel-Token"
    return resp

# =========================
# DB
# =========================

def db() -> sqlite3.Connection:
    conn = sqlite3.connect(CONFIG["DB_PATH"], timeout=10)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with db() as conn:
        conn.executescript(
            """
            PRAGMA journal_mode = WAL;
            CREATE TABLE IF NOT EXISTS webhook_seen (
              id TEXT PRIMARY KEY,
              seen_at INTEGER
            );
            CREATE TABLE IF NOT EXISTS pixel_seen (
              id TEXT PRIMARY KEY,
              seen_at INTEGER
            );
            CREATE TABLE IF NOT EXISTS sku_totals (
              sku TEXT PRIMARY KEY,
              views_total INTEGER NOT NULL DEFAULT 0,
              atc_total   INTEGER NOT NULL DEFAULT 0,
              sales_total INTEGER NOT NULL DEFAULT 0,
              updated_at  INTEGER
            );
            CREATE TABLE IF NOT EXISTS inv_baseline (
              shop TEXT NOT NULL,
              inventory_item_id INTEGER NOT NULL,
              last_available INTEGER,
              PRIMARY KEY (shop, inventory_item_id)
            );
            CREATE TABLE IF NOT EXISTS sku_map (
              shop TEXT NOT NULL,
              product_id INTEGER NOT NULL,
              sku TEXT NOT NULL,
              PRIMARY KEY (shop, product_id)
            );
            """
        )

init_db()

# =========================
# Logging helpers (human-friendly)
# =========================

def ts_ist() -> str:
    return (datetime.utcnow() + timedelta(hours=5, minutes=30)).strftime("%Y-%m-%d %H:%M:%S IST")

def log_line(msg: str) -> None:
    print(f"[{ts_ist()}] {msg}")

# =========================
# Shopify HTTP / GraphQL helpers
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
    try:
        return int((gid_str or "").rsplit("/", 1)[-1])
    except Exception:
        return 0

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

# ---------- Title & SKU helpers ----------

def get_product_title_by_product_id(shop: str, product_id: int) -> str:
    if not product_id:
        return ""
    q = """query($id: ID!){ product(id:$id){ title } }"""
    try:
        data = graphql(shop, q, {"id": gid("Product", product_id)})
        return ((data.get("product") or {}).get("title") or "").strip()
    except Exception as e:
        print(f"[WARN] title lookup failed on {shop} for product_id={product_id}: {e}")
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
        print(f"[WARN] inventory→variant→product info failed on {shop} for inventory_item_id={inventory_item_id}: {e}")
        return None, None, ""

def get_sku_from_product_id(shop: str, product_id: int) -> Optional[str]:
    if not product_id:
        return None
    # cache first
    with db() as conn:
        row = conn.execute(
            "SELECT sku FROM sku_map WHERE shop=? AND product_id=?",
            (shop, product_id),
        ).fetchone()
        if row:
            return (row["sku"] or "").strip() or None
    q = """
    query($id: ID!) {
      product(id:$id) { variants(first:1){ nodes{ sku } } }
    }"""
    try:
        data = graphql(shop, q, {"id": gid("Product", product_id)})
        nodes = ((data.get("product") or {}).get("variants") or {}).get("nodes") or []
        if nodes:
            sku = (nodes[0].get("sku") or "").strip()
            if sku:
                with db() as conn:
                    conn.execute(
                        "INSERT OR REPLACE INTO sku_map(shop,product_id,sku) VALUES (?,?,?)",
                        (shop, product_id, sku),
                    )
                return sku
    except Exception as e:
        print(f"[WARN] sku_from_product_id failed on {shop} for product_id={product_id}: {e}")
    return None

def get_primary_product_by_sku(sku: str) -> Tuple[Optional[int], Optional[int]]:
    if not sku:
        return None, None
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
                if pid:
                    return pid, vid or None
    except Exception as e:
        print(f"[WARN] primary_by_sku failed for sku={sku}: {e}")
    return None, None

# ---------- Metafield writers ----------

def set_product_metafields_primary(product_id: int, fields: dict):
    """
    fields: { (namespace, key, type): value_string }
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
    mutation($metafields: [MetafieldsSetInput!]!) {
      metafieldsSet(metafields:$metafields) {
        userErrors { field message }
      }
    }"""
    try:
        graphql("com", m, {"metafields": metas})
    except Exception as e:
        print(f"[WARN] metafieldsSet primary failed: {e}")

def adjust_badges_and_delivery(shop: str, product_id: int, available_now: int):
    if not product_id:
        return
    if shop == "com" and CONFIG["WRITE_BADGES_COM"] != "1":
        return
    if shop == "us" and CONFIG["WRITE_BADGES_US"] != "1":
        return
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
    # write on the shop where the change happened
    metas = []
    for (ns_, key, mtype), value in fields.items():
        metas.append({
            "ownerId": gid("Product", product_id),
            "namespace": ns_,
            "key": key,
            "type": mtype,
            "value": str(value),
        })
    m = """
    mutation($metafields: [MetafieldsSetInput!]!) {
      metafieldsSet(metafields:$metafields) {
        userErrors { field message }
      }
    }"""
    try:
        graphql(shop, m, {"metafields": metas})
    except Exception as e:
        print(f"[WARN] adjust badges/delivery failed on {shop}: {e}")

def bump_primary_sales(sku: str, delta_sales: int):
    if delta_sales <= 0 or not sku:
        return
    pid, _ = get_primary_product_by_sku(sku)
    if not pid:
        return
    # Read current totals (sales_total & sales_dates)
    q = """
    query($id: ID!) {
      product(id:$id) {
        title
        sales_total: metafield(namespace:"custom", key:"sales_total"){ value type }
        sales_dates: metafield(namespace:"custom", key:"sales_dates"){ value type }
      }
    }"""
    cur_total = 0
    cur_dates = []
    try:
        data = graphql("com", q, {"id": gid("Product", pid)})
        p = data.get("product") or {}
        st = p.get("sales_total")
        sd = p.get("sales_dates")
        if st and st.get("type") == "number_integer" and st.get("value"):
            cur_total = int(st["value"])
        if sd and sd.get("type") == "list.date" and sd.get("value"):
            cur_dates = json.loads(sd["value"])
    except Exception as e:
        print(f"[WARN] read sales metafields failed: {e}")

    new_total = cur_total + int(delta_sales)
    today = (datetime.utcnow() + timedelta(hours=5, minutes=30)).strftime("%Y-%m-%d")
    if today not in cur_dates:
        cur_dates.append(today)

    set_product_metafields_primary(pid, {
        ("custom", "sales_total", "number_integer"): str(new_total),
        ("custom", "sales_dates", "list.date"): json.dumps(cur_dates),
    })

    # mirror in local table
    with db() as conn:
        conn.execute(
            """INSERT INTO sku_totals(sku, views_total, atc_total, sales_total, updated_at)
               VALUES (?,0,0,?,?)
               ON CONFLICT(sku) DO UPDATE SET sales_total=sales_total+excluded.sales_total, updated_at=excluded.updated_at""",
            (sku, int(delta_sales), int(time.time()))
        )

def bump_primary_views_or_atc_from_pixel(shop_host: str, product_id: int, kind: str, qty: int):
    """
    kind: "product" (view) or "atc" (add to cart)
    1) Resolve SKU from sending shop's product_id
    2) Map SKU to primary product
    3) Increment metafield on primary
    4) Log a friendly line with product title
    """
    # Determine sending shop by host
    shop = "us" if ("rudradhan.us" in shop_host) else "com"

    sku = get_sku_from_product_id(shop, product_id)
    title_src = get_product_title_by_product_id(shop, product_id)
    show_shop = ".us" if shop == "us" else ".com"

    pid_primary, _ = get_primary_product_by_sku(sku) if sku else (None, None)
    if not pid_primary:
        action = "VIEWED" if kind == "product" else f"ADDED TO CART ×{max(1, qty)}"
        log_line(f"[{show_shop}] {action}: {title_src or '(unknown title)'} (ProductID={product_id}{' | SKU: '+sku if sku else ''})")
        return

    field_key = "views_total" if kind == "product" else "added_to_cart_total"
    q = f"""
    query($id: ID!) {{
      product(id:$id) {{
        title
        mf: metafield(namespace:"custom", key:"{field_key}") {{ value type }}
      }}
    }}"""
    try:
        data = graphql("com", q, {"id": gid("Product", pid_primary)})
        p = data.get("product") or {}
        primary_title = (p.get("title") or "").strip()
        mf = p.get("mf")
        cur = 0
        if mf and mf.get("type") == "number_integer" and mf.get("value"):
            cur = int(mf["value"])
        new_val = cur + int(max(1, qty))
        set_product_metafields_primary(pid_primary, {
            ("custom", field_key, "number_integer"): str(new_val)
        })

        if kind == "product":
            log_line(f"[{show_shop}] VIEWED: {primary_title or title_src or '(unknown title)'} (SKU: {sku or '—'}) → views_total={new_val}")
        else:
            log_line(f"[{show_shop}] ADDED TO CART ×{max(1, qty)}: {primary_title or title_src or '(unknown title)'} (SKU: {sku or '—'}) → added_to_cart_total={new_val}")

        # mirror in local table
        with db() as conn:
            if field_key == "views_total":
                conn.execute(
                    """INSERT INTO sku_totals(sku, views_total, atc_total, sales_total, updated_at)
                       VALUES (?,?,0,0,?)
                       ON CONFLICT(sku) DO UPDATE SET views_total=views_total+excluded.views_total, updated_at=excluded.updated_at""",
                    (sku or "", int(qty), int(time.time()))
                )
            else:
                conn.execute(
                    """INSERT INTO sku_totals(sku, views_total, atc_total, sales_total, updated_at)
                       VALUES (?,0,?,0,?)
                       ON CONFLICT(sku) DO UPDATE SET atc_total=atc_total+excluded.atc_total, updated_at=excluded.updated_at""",
                    (sku or "", int(qty), int(time.time()))
                )
    except Exception as e:
        print(f"[WARN] pixel bump failed: {e}")

# =========================
# Routes
# =========================

@app.route("/", methods=["GET", "HEAD"])
def root_ok():
    return "OK", 200

@app.route("/healthz", methods=["GET"])
def healthz():
    return jsonify({"ok": True}), 200

# ----- Inventory webhook: .com -----

@app.route("/webhooks/com/inventory", methods=["POST"])
def com_inventory():
    raw = request.get_data(cache=True)
    if not verify_shopify_hmac(raw, request.headers.get("X-Shopify-Hmac-Sha256", ""), CONFIG["COM_WEBHOOK_SECRET"]):
        abort(401)
    if request.headers.get("X-Shopify-Topic", "") != "inventory_levels/update":
        return "", 200

    webhook_id = request.headers.get("X-Shopify-Webhook-Id", "")
    with db() as conn:
        if conn.execute("SELECT 1 FROM webhook_seen WHERE id=?", (webhook_id,)).fetchone():
            return "", 200
        conn.execute("INSERT OR IGNORE INTO webhook_seen(id, seen_at) VALUES (?,?)", (webhook_id, int(time.time())))

    payload = request.get_json(force=True)
    inv_id = int(payload.get("inventory_item_id"))
    available = int(payload.get("available"))

    sku, product_id, product_title = get_variant_product_info_from_inventory("com", inv_id)

    with db() as conn:
        row = conn.execute(
            "SELECT last_available FROM inv_baseline WHERE shop=? AND inventory_item_id=?",
            ("com", inv_id),
        ).fetchone()
        prev = int(row["last_available"]) if (row and row["last_available"] is not None) else None
        conn.execute(
            "INSERT OR REPLACE INTO inv_baseline(shop, inventory_item_id, last_available) VALUES (?,?,?)",
            ("com", inv_id, available),
        )

    if prev is None or prev == available:
        log_line(f"[.com] AVAILABILITY: {product_title or '(unknown title)'} (SKU: {sku or '—'}) prev: {prev if prev is not None else '—'} → new: {available} (inv_item_id={inv_id})")
        adjust_badges_and_delivery("com", product_id or 0, available)
        return "", 200

    delta = available - prev
    if delta < 0 and sku:
        bump_primary_sales(sku, -delta)

    log_line(f"[.com] AVAILABILITY: {product_title or '(unknown title)'} (SKU: {sku or '—'}) prev: {prev} → new: {available} (Δ={delta}, inv_item_id={inv_id})")
    adjust_badges_and_delivery("com", product_id or 0, available)
    return "", 200

# ----- Inventory webhook: .us -----

@app.route("/webhooks/us/inventory", methods=["POST"])
def us_inventory():
    raw = request.get_data(cache=True)
    if not verify_shopify_hmac(raw, request.headers.get("X-Shopify-Hmac-Sha256", ""), CONFIG["US_WEBHOOK_SECRET"]):
        abort(401)
    if request.headers.get("X-Shopify-Topic", "") != "inventory_levels/update":
        return "", 200

    webhook_id = request.headers.get("X-Shopify-Webhook-Id", "")
    with db() as conn:
        if conn.execute("SELECT 1 FROM webhook_seen WHERE id=?", (webhook_id,)).fetchone():
            return "", 200
        conn.execute("INSERT OR IGNORE INTO webhook_seen(id, seen_at) VALUES (?,?)", (webhook_id, int(time.time())))

    payload = request.get_json(force=True)
    inv_id = int(payload.get("inventory_item_id"))
    available = int(payload.get("available"))

    sku, product_id, product_title = get_variant_product_info_from_inventory("us", inv_id)

    with db() as conn:
        row = conn.execute(
            "SELECT last_available FROM inv_baseline WHERE shop=? AND inventory_item_id=?",
            ("us", inv_id),
        ).fetchone()
        prev = int(row["last_available"]) if (row and row["last_available"] is not None) else None
        conn.execute(
            "INSERT OR REPLACE INTO inv_baseline(shop, inventory_item_id, last_available) VALUES (?,?,?)",
            ("us", inv_id, available),
        )

    if prev is None or prev == available:
        log_line(f"[.us] AVAILABILITY: {product_title or '(unknown title)'} (SKU: {sku or '—'}) prev: {prev if prev is not None else '—'} → new: {available} (inv_item_id={inv_id})")
        adjust_badges_and_delivery("us", product_id or 0, available)
        return "", 200

    delta = available - prev
    if delta < 0 and sku:
        bump_primary_sales(sku, -delta)

    log_line(f"[.us] AVAILABILITY: {product_title or '(unknown title)'} (SKU: {sku or '—'}) prev: {prev} → new: {available} (Δ={delta}, inv_item_id={inv_id})")
    adjust_badges_and_delivery("us", product_id or 0, available)
    return "", 200

# ----- Pixel endpoints (YOUR existing contract) -----

@app.route("/track/product", methods=["POST"])
def track_product():
    if request.args.get("key") != CONFIG["PIXEL_SHARED_SECRET"]:
        abort(401)
    body = request.get_json(force=True, silent=True) or {}
    product_id = int(body.get("productId") or 0)
    shop_host = (body.get("shop") or "").lower()
    if product_id <= 0 or not shop_host:
        return "", 200

    # Dedup using coarse key if no event_id present
    ev_id = body.get("event_id") or f"{shop_host}:product:{product_id}:{int(body.get('ts') or 0)}"
    with db() as conn:
        if conn.execute("SELECT 1 FROM pixel_seen WHERE id=?", (ev_id,)).fetchone():
            return "", 200
        conn.execute("INSERT OR IGNORE INTO pixel_seen(id, seen_at) VALUES (?,?)", (ev_id, int(time.time())))

    bump_primary_views_or_atc_from_pixel(shop_host, product_id, "product", 1)
    return "", 200

@app.route("/track/atc", methods=["POST"])
def track_atc():
    if request.args.get("key") != CONFIG["PIXEL_SHARED_SECRET"]:
        abort(401)
    body = request.get_json(force=True, silent=True) or {}
    product_id = int(body.get("productId") or 0)
    qty = int(body.get("qty") or 1)
    shop_host = (body.get("shop") or "").lower()
    if product_id <= 0 or not shop_host:
        return "", 200

    ev_id = body.get("event_id") or f"{shop_host}:atc:{product_id}:{int(body.get('ts') or 0)}"
    with db() as conn:
        if conn.execute("SELECT 1 FROM pixel_seen WHERE id=?", (ev_id,)).fetchone():
            return "", 200
        conn.execute("INSERT OR IGNORE INTO pixel_seen(id, seen_at) VALUES (?,?)", (ev_id, int(time.time())))

    bump_primary_views_or_atc_from_pixel(shop_host, product_id, "atc", max(1, qty))
    return "", 200

# ----- Optional: alias endpoint for any clients calling /events/pixel -----

@app.route("/events/pixel", methods=["POST", "OPTIONS"])
def events_pixel():
    if request.method == "OPTIONS":
        return "", 200
    # accept either header or ?key
    header_token = request.headers.get("X-Pixel-Token", "")
    qs_key = request.args.get("key", "")
    if (CONFIG.get("PIXEL_SHARED_SECRET") or "") not in (header_token, qs_key):
        return "", 401
    body = request.get_json(force=True, silent=True) or {}
    evt = (body.get("type") or "product_viewed").strip()
    shop_host = (body.get("shop") or "").lower()
    product_id = int(body.get("productId") or 0)
    qty = int(body.get("qty") or 1)
    ev_id = body.get("event_id") or f"{shop_host}:{evt}:{product_id}:{int(body.get('ts') or 0)}"
    with db() as conn:
        if conn.execute("SELECT 1 FROM pixel_seen WHERE id=?", (ev_id,)).fetchone():
            return "", 200
        conn.execute("INSERT OR IGNORE INTO pixel_seen(id, seen_at) VALUES (?,?)", (ev_id, int(time.time())))
    if evt == "product_added_to_cart":
        if product_id > 0 and shop_host:
            bump_primary_views_or_atc_from_pixel(shop_host, product_id, "atc", max(1, qty))
        return "", 200
    # default → treat as product_viewed
    if product_id > 0 and shop_host:
        bump_primary_views_or_atc_from_pixel(shop_host, product_id, "product", 1)
    return "", 200

# =========================
# Entrypoint
# =========================

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "10000")))
