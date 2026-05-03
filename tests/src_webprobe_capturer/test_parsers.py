"""Tests for the shared artifact parsers (CA017).

Each parser must be graceful on malformed input (CO005), record elapsed_ms
(CO011), and produce a JSON-serializable payload.
"""

from __future__ import annotations

import json

from webprobe.parsers import json_ld, meta_tags, openapi, robots_txt, sitemap


# ---- robots_txt ----


def test_robots_basic() -> None:
    text = (
        "# top comment\n"
        "User-agent: *\n"
        "Allow: /\n"
        "\n"
        "User-agent: GPTBot\n"
        "Disallow: /private/\n"
        "\n"
        "Sitemap: https://x.test/sitemap.xml\n"
        "Content-Signal: ai-train=yes, search=yes\n"
    )
    r = robots_txt.parse(text)
    assert r.ok
    assert r.elapsed_ms >= 0
    assert len(r.payload["groups"]) == 2
    assert r.payload["sitemaps"] == ["https://x.test/sitemap.xml"]
    assert r.payload["content_signals"][0]["signals"]["ai-train"] == "yes"


def test_robots_empty_returns_not_ok() -> None:
    r = robots_txt.parse("")
    assert not r.ok
    assert r.error == "empty_payload"


def test_robots_garbage_does_not_raise() -> None:
    r = robots_txt.parse("\x00\xff\xfegarbage\n!!!\n")
    # Either returns ok with warnings, or returns ok with no groups.
    # Importantly, it does not raise.
    assert r.elapsed_ms >= 0


def test_robots_evaluate_explicit_overrides_star() -> None:
    text = "User-agent: *\nAllow: /\n\nUser-agent: GPTBot\nDisallow: /\n"
    r = robots_txt.parse(text)
    assert r.ok
    decision = robots_txt.evaluate(r.payload, user_agent="GPTBot", target_path="/")
    assert decision["decision"] == "disallow"
    assert decision["matched_group"] == "GPTBot"

    decision_other = robots_txt.evaluate(r.payload, user_agent="OtherBot", target_path="/")
    assert decision_other["decision"] == "allow"
    assert decision_other["matched_group"] == "*"


def test_robots_evaluate_path_specificity() -> None:
    text = "User-agent: *\nAllow: /\nDisallow: /private/\n"
    r = robots_txt.parse(text)
    assert robots_txt.evaluate(r.payload, user_agent="x", target_path="/")["decision"] == "allow"
    assert robots_txt.evaluate(r.payload, user_agent="x", target_path="/private/")["decision"] == "disallow"


def test_robots_evaluate_matrix_default() -> None:
    text = "User-agent: *\nAllow: /\n"
    r = robots_txt.parse(text)
    matrix = robots_txt.evaluate_matrix(r.payload, target_path="/")
    assert "GPTBot" in matrix
    assert all(m["decision"] == "allow" for m in matrix.values())


# ---- sitemap ----


_SM_URLSET = (
    '<?xml version="1.0"?>'
    '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
    '<url><loc>https://x/a</loc><lastmod>2026-01-01</lastmod></url>'
    '<url><loc>https://x/b</loc></url>'
    '</urlset>'
)

_SM_INDEX = (
    '<?xml version="1.0"?>'
    '<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
    '<sitemap><loc>https://x/a.xml</loc></sitemap>'
    '</sitemapindex>'
)


def test_sitemap_urlset() -> None:
    r = sitemap.parse(_SM_URLSET)
    assert r.ok
    assert r.payload["kind"] == "urlset"
    assert len(r.payload["urls"]) == 2
    assert r.payload["urls"][0]["loc"] == "https://x/a"
    assert r.payload["urls"][0]["lastmod"] == "2026-01-01"


def test_sitemap_index() -> None:
    r = sitemap.parse(_SM_INDEX)
    assert r.ok
    assert r.payload["kind"] == "sitemapindex"
    assert len(r.payload["sitemaps"]) == 1


def test_sitemap_malformed_xml() -> None:
    r = sitemap.parse("<not><valid")
    assert not r.ok
    assert "xml_parse_error" in r.error


def test_sitemap_unknown_root() -> None:
    r = sitemap.parse('<?xml version="1.0"?><foo></foo>')
    assert not r.ok
    assert "unknown_root_element" in r.error


# ---- openapi ----


def test_openapi_minimal_json() -> None:
    doc = {
        "openapi": "3.0.0",
        "info": {"title": "x", "version": "1"},
        "paths": {
            "/foo": {
                "get": {
                    "summary": "list",
                    "description": "list things",
                    "responses": {
                        "200": {
                            "description": "ok",
                            "content": {
                                "application/json": {
                                    "schema": {"type": "array"},
                                    "example": [{"id": 1}],
                                }
                            },
                        },
                        "400": {
                            "description": "bad",
                            "content": {"application/json": {"schema": {}}},
                        },
                    },
                }
            }
        },
        "components": {"securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}}},
    }
    r = openapi.parse(json.dumps(doc))
    assert r.ok
    assert r.payload["operation_count"] == 1
    assert "200" in r.payload["response_codes_used"]
    assert "400" in r.payload["response_codes_used"]
    assert r.payload["error_responses_total"] == 1
    assert r.payload["error_responses_with_schemas"] == 1
    assert r.payload["operations_with_descriptions"] == 1
    assert r.payload["operations_with_examples"] == 1
    assert r.payload["security_schemes"] == ["bearer"]


def test_openapi_yaml() -> None:
    text = """
openapi: 3.0.0
info:
  title: x
  version: '1'
paths:
  /foo:
    get:
      responses:
        '200':
          description: ok
"""
    r = openapi.parse(text)
    assert r.ok
    assert r.payload["operation_count"] == 1


def test_openapi_garbage() -> None:
    r = openapi.parse("{garbage")
    assert not r.ok
    assert r.error  # populated


def test_openapi_empty() -> None:
    r = openapi.parse("")
    assert not r.ok


# ---- json_ld ----


def test_jsonld_product_with_offer() -> None:
    html = (
        '<script type="application/ld+json">'
        '{"@context":"https://schema.org","@type":"Product","name":"P",'
        '"offers":{"@type":"Offer","price":"19.99","priceCurrency":"USD"}}'
        '</script>'
    )
    r = json_ld.parse(html)
    assert r.ok
    assert "Product" in r.payload["types"]
    products = r.payload["types"]["Product"]
    assert len(products) == 1
    assert json_ld.field_value(products[0], "name") == "P"
    offers = json_ld.find_offers(products[0])
    assert len(offers) == 1
    assert offers[0]["price"] == "19.99"


def test_jsonld_no_blocks() -> None:
    r = json_ld.parse("<html><head></head></html>")
    assert not r.ok
    assert r.error == "no_jsonld_blocks_found"


def test_jsonld_malformed_block_does_not_kill_others() -> None:
    html = (
        '<script type="application/ld+json">{not json</script>'
        '<script type="application/ld+json">'
        '{"@type":"Organization","name":"Org"}'
        '</script>'
    )
    r = json_ld.parse(html)
    assert r.ok  # second block succeeded
    assert "Organization" in r.payload["types"]
    # Warnings record the bad block
    assert any("json_parse_error_in_block" in w for w in r.warnings)


def test_jsonld_graph_flatten() -> None:
    html = (
        '<script type="application/ld+json">'
        '{"@context":"https://schema.org","@graph":['
        '{"@type":"Product","name":"P"},'
        '{"@type":"Organization","name":"Org"}'
        ']}</script>'
    )
    r = json_ld.parse(html)
    assert "Product" in r.payload["types"]
    assert "Organization" in r.payload["types"]


# ---- meta_tags ----


_META_HTML = (
    '<!DOCTYPE html>'
    '<html lang="en">'
    '<head>'
    '<title>Test Page</title>'
    '<meta name="description" content="A test page about widgets.">'
    '<meta name="viewport" content="width=device-width">'
    '<meta property="og:title" content="OG Title">'
    '<meta property="og:image" content="https://x/og.png">'
    '<meta name="twitter:card" content="summary">'
    '<meta name="twitter:title" content="TW Title">'
    '<link rel="canonical" href="https://x/canonical">'
    '<link rel="alternate" hreflang="es" href="https://x/es">'
    '<link rel="service-doc" href="/docs">'
    '</head>'
    '<body><h1>Hi</h1><h2>Sub</h2><img src="a" alt="alpha"><img src="b"></body>'
    '</html>'
)


def test_meta_basic_extraction() -> None:
    r = meta_tags.parse(_META_HTML)
    assert r.ok
    p = r.payload
    assert p["lang"] == "en"
    assert p["title"] == "Test Page"
    assert 30 <= p["title_length"] <= 60 or p["title_length"] == len("Test Page")
    assert p["description"].startswith("A test page")
    assert p["og"]["title"] == "OG Title"
    assert p["og"]["image"] == "https://x/og.png"
    assert p["twitter"]["card"] == "summary"
    assert p["canonical"] == "https://x/canonical"
    assert any(a["hreflang"] == "es" for a in p["alternates"])
    assert any(rel["rel"] == "service-doc" for rel in p["well_known_relations"])
    assert p["headings"]["h1"] == ["Hi"]
    assert p["alt_text_coverage"] == 0.5  # 1 of 2 images has alt


def test_meta_link_header_parse() -> None:
    r = meta_tags.parse(
        "<html></html>",
        link_header_values=[
            '</.well-known/api-catalog>; rel="api-catalog", </docs>; rel="service-doc"',
        ],
    )
    assert r.ok
    rels = {lh["rel"] for lh in r.payload["link_headers"]}
    assert "api-catalog" in rels
    assert "service-doc" in rels


def test_meta_no_images_alt_coverage_none() -> None:
    r = meta_tags.parse("<html><head><title>x</title></head></html>")
    assert r.payload["alt_text_coverage"] is None
