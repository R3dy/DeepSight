"""
OpenAPI / Swagger Documentation for the v2 API.

Serves the OpenAPI 3.0 spec at /api/v2/openapi.json and Swagger UI at /api/v2/docs/.
"""

import os
import time

from flask import jsonify, request, send_file

from routes.v2 import v2_bp, auth

# ── OpenAPI 3.0 Specification ──

_OPENAPI_SPEC = None


def _build_openapi_spec():
    """Build the OpenAPI 3.0 specification for the v2 API."""
    return {
        "openapi": "3.0.3",
        "info": {
            "title": "DeepSight Enterprise SIEM — API v2",
            "description": (
                "Versioned API for the DeepSight Enterprise SIEM platform. "
                "All endpoints (except /api/v2/health and /api/v2/docs/) require "
                "authentication via Bearer token."
            ),
            "version": "2.0.0-alpha",
            "contact": {
                "name": "DeepSight Security",
                "url": "https://github.com/your-org/deepsight",
            },
            "license": {
                "name": "AGPLv3",
                "url": "https://www.gnu.org/licenses/agpl-3.0.html",
            },
        },
        "servers": [
            {"url": "http://127.0.0.1:8451", "description": "Local development server"},
        ],
        "components": {
            "securitySchemes": {
                "bearerAuth": {
                    "type": "http",
                    "scheme": "bearer",
                    "bearerFormat": "JWT / API Key",
                    "description": (
                        "Session token from POST /api/auth/login, "
                        "or API key from POST /api/auth/api-keys"
                    ),
                },
            },
            "schemas": {
                "Error": {
                    "type": "object",
                    "properties": {
                        "error": {"type": "string", "description": "Error code"},
                        "reason": {"type": "string", "description": "Human-readable explanation"},
                    },
                },
                "Status": {
                    "type": "object",
                    "properties": {
                        "data": {
                            "type": "object",
                            "properties": {
                                "version": {"type": "string"},
                                "status": {"type": "string"},
                                "timestamp": {"type": "number"},
                                "features": {"type": "object"},
                            },
                        },
                    },
                },
            },
            "responses": {
                "Unauthorized": {
                    "description": "Missing or invalid authentication",
                    "content": {
                        "application/json": {
                            "schema": {"$ref": "#/components/schemas/Error"},
                        },
                    },
                },
                "Forbidden": {
                    "description": "Insufficient permissions",
                    "content": {
                        "application/json": {
                            "schema": {"$ref": "#/components/schemas/Error"},
                        },
                    },
                },
            },
        },
        "security": [{"bearerAuth": []}],
        "paths": {
            "/api/v2/health": {
                "get": {
                    "summary": "Public health check",
                    "description": "Returns API health status. No authentication required.",
                    "tags": ["System"],
                    "security": [],
                    "responses": {
                        "200": {
                            "description": "API is healthy",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "data": {
                                                "type": "object",
                                                "properties": {
                                                    "status": {"type": "string", "example": "healthy"},
                                                    "version": {"type": "string", "example": "2.0.0-alpha"},
                                                    "timestamp": {"type": "number"},
                                                },
                                            },
                                        },
                                    },
                                },
                            },
                        },
                    },
                },
            },
            "/api/v2/status": {
                "get": {
                    "summary": "API v2 status and feature availability",
                    "description": "Returns the operational status of the v2 API and planned features.",
                    "tags": ["System"],
                    "responses": {
                        "200": {
                            "description": "Status retrieved",
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/Status"},
                                },
                            },
                        },
                        "401": {"$ref": "#/components/responses/Unauthorized"},
                    },
                },
            },
            "/api/v2/cases": {
                "get": {
                    "summary": "List cases (planned)",
                    "description": "List all incident cases. Planned for M3.",
                    "tags": ["Cases"],
                    "responses": {
                        "200": {"description": "Cases listed"},
                        "401": {"$ref": "#/components/responses/Unauthorized"},
                    },
                },
                "post": {
                    "summary": "Create case (planned)",
                    "description": "Create a new incident case. Planned for M3.",
                    "tags": ["Cases"],
                    "responses": {
                        "201": {"description": "Case created"},
                        "401": {"$ref": "#/components/responses/Unauthorized"},
                    },
                },
            },
            "/api/v2/hunt/queries": {
                "get": {
                    "summary": "List hunt queries (planned)",
                    "description": "List saved threat hunt queries. Planned for M5.",
                    "tags": ["Hunting"],
                    "responses": {
                        "200": {"description": "Queries listed"},
                        "401": {"$ref": "#/components/responses/Unauthorized"},
                    },
                },
            },
            "/api/v2/iocs": {
                "get": {
                    "summary": "List IOCs (planned)",
                    "description": "List indicators of compromise. Planned for M5.",
                    "tags": ["IOCs"],
                    "responses": {
                        "200": {"description": "IOCs listed"},
                        "401": {"$ref": "#/components/responses/Unauthorized"},
                    },
                },
            },
            "/api/v2/dashboards": {
                "get": {
                    "summary": "List dashboards (planned)",
                    "description": "List custom dashboards. Planned for M6.",
                    "tags": ["Dashboards"],
                    "responses": {
                        "200": {"description": "Dashboards listed"},
                        "401": {"$ref": "#/components/responses/Unauthorized"},
                    },
                },
            },
            "/api/v2/playbooks": {
                "get": {
                    "summary": "List playbooks (planned)",
                    "description": "List SOAR playbooks. Planned for M6.",
                    "tags": ["Playbooks"],
                    "responses": {
                        "200": {"description": "Playbooks listed"},
                        "401": {"$ref": "#/components/responses/Unauthorized"},
                    },
                },
            },
            "/api/v2/admin/users": {
                "get": {
                    "summary": "List users (planned)",
                    "description": "Admin user management. Planned for M4.",
                    "tags": ["Admin"],
                    "responses": {
                        "200": {"description": "Users listed"},
                        "401": {"$ref": "#/components/responses/Unauthorized"},
                    },
                },
            },
            "/api/v2/sigma/rules": {
                "get": {
                    "summary": "List Sigma rules (planned)",
                    "description": "List detection rules. Planned for M2.",
                    "tags": ["Detection"],
                    "responses": {
                        "200": {"description": "Rules listed"},
                        "401": {"$ref": "#/components/responses/Unauthorized"},
                    },
                },
            },
            "/api/auth/login": {
                "post": {
                    "summary": "Authenticate user",
                    "description": "Login with username/password to receive a session token.",
                    "tags": ["Authentication"],
                    "security": [],
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "required": ["username", "password"],
                                    "properties": {
                                        "username": {"type": "string"},
                                        "password": {"type": "string", "format": "password"},
                                    },
                                },
                            },
                        },
                    },
                    "responses": {
                        "200": {
                            "description": "Login successful",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "token": {"type": "string"},
                                            "expires_at": {"type": "string", "format": "date-time"},
                                            "user": {
                                                "type": "object",
                                                "properties": {
                                                    "id": {"type": "integer"},
                                                    "username": {"type": "string"},
                                                    "is_admin": {"type": "boolean"},
                                                },
                                            },
                                        },
                                    },
                                },
                            },
                        },
                        "401": {"$ref": "#/components/responses/Unauthorized"},
                        "429": {"description": "Rate limited — too many attempts"},
                    },
                },
            },
            "/api/auth/logout": {
                "post": {
                    "summary": "Logout / revoke token",
                    "description": "Revoke the current session token.",
                    "tags": ["Authentication"],
                    "responses": {
                        "200": {"description": "Token revoked"},
                        "401": {"$ref": "#/components/responses/Unauthorized"},
                    },
                },
            },
            "/api/auth/status": {
                "get": {
                    "summary": "Get token status",
                    "description": "Return info about the current authenticated session.",
                    "tags": ["Authentication"],
                    "responses": {
                        "200": {"description": "Session info"},
                        "401": {"$ref": "#/components/responses/Unauthorized"},
                    },
                },
            },
            "/api/auth/api-keys": {
                "get": {
                    "summary": "List API keys",
                    "description": "List API keys for the current user.",
                    "tags": ["Authentication"],
                    "responses": {
                        "200": {"description": "API keys listed"},
                        "401": {"$ref": "#/components/responses/Unauthorized"},
                    },
                },
                "post": {
                    "summary": "Create API key",
                    "description": "Create a new API key for programmatic access.",
                    "tags": ["Authentication"],
                    "responses": {
                        "201": {"description": "API key created"},
                        "401": {"$ref": "#/components/responses/Unauthorized"},
                    },
                },
            },
        },
        "tags": [
            {"name": "System", "description": "Health and status endpoints"},
            {"name": "Authentication", "description": "Login, logout, token and API key management"},
            {"name": "Cases", "description": "Incident case management (M3)"},
            {"name": "Hunting", "description": "Threat hunting queries (M5)"},
            {"name": "IOCs", "description": "Indicators of compromise (M5)"},
            {"name": "Dashboards", "description": "Custom dashboards (M6)"},
            {"name": "Playbooks", "description": "SOAR playbook engine (M6)"},
            {"name": "Admin", "description": "Administrative operations (M4)"},
            {"name": "Detection", "description": "Detection engine management (M2)"},
        ],
    }


def get_openapi_spec():
    """Get the cached OpenAPI spec, building it on first access."""
    global _OPENAPI_SPEC
    if _OPENAPI_SPEC is None:
        _OPENAPI_SPEC = _build_openapi_spec()
    return _OPENAPI_SPEC


# ── Swagger UI HTML (self-contained, no CDN dependencies) ──

_SWAGGER_UI_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>DeepSight API v2 — Swagger</title>
<link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css">
<style>
  html { box-sizing: border-box; overflow-y: scroll; }
  *, *:before, *:after { box-sizing: inherit; }
  body { margin: 0; background: #0f172a; }
  .swagger-ui .topbar { background-color: #1e293b; }
  .swagger-ui .topbar .download-url-wrapper .select-label { color: #e2e8f0; }
  .swagger-ui .info .title { color: #f8fafc; }
  .swagger-ui .scheme-container { background: #1e293b; box-shadow: none; }
  .swagger-ui .opblock-tag, .swagger-ui .opblock .opblock-summary-description { color: #cbd5e1; }
  .swagger-ui .markdown p, .swagger-ui .markdown li { color: #94a3b8; }
  .swagger-ui .opblock .opblock-section-header { background: #1e293b; }
  .swagger-ui .opblock .opblock-section-header h4 { color: #e2e8f0; }
  .swagger-ui .opblock .opblock-summary-method { border-radius: 4px; }
  .swagger-ui .response-col_status, .swagger-ui .response-col_description { color: #94a3b8; }
  .swagger-ui table thead tr th { color: #94a3b8; border-bottom-color: #334155; }
  .swagger-ui .parameter__name { color: #e2e8f0; }
  .swagger-ui .parameter__type { color: #94a3b8; }
  .swagger-ui .model-box { background: #1e293b; }
  .swagger-ui .model-title { color: #e2e8f0; }
  .swagger-ui .tab li button.tablinks { color: #94a3b8; }
  .swagger-ui .btn { border-radius: 4px; }
  .swagger-ui .info a { color: #7c3aed; }
</style>
</head>
<body>
<div id="swagger-ui"></div>
<script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js" crossorigin></script>
<script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-standalone-preset.js" crossorigin></script>
<script>
window.onload = function() {
  SwaggerUIBundle({
    url: "/api/v2/openapi.json",
    dom_id: "#swagger-ui",
    deepLinking: true,
    presets: [SwaggerUIBundle.presets.apis, SwaggerUIStandalonePreset],
    plugins: [SwaggerUIBundle.plugins.DownloadUrl],
    layout: "StandaloneLayout",
    defaultModelsExpandDepth: 1,
    defaultModelExpandDepth: 1,
    docExpansion: "list",
    filter: true,
    showExtensions: true,
    showCommonExtensions: true,
  });
};
</script>
</body>
</html>"""


# ═══════════════════════════════════════════
# Documentation Routes
# ═══════════════════════════════════════════


@v2_bp.route("/openapi.json")
@auth.require_auth
def openapi_json():
    """Serve the OpenAPI 3.0 specification as JSON."""
    spec = get_openapi_spec()
    # Add server URL from request
    spec = dict(spec)  # shallow copy
    spec["servers"] = [
        {"url": request.host_url.rstrip("/"), "description": "Current server"},
    ]
    return jsonify(spec)


@v2_bp.route("/docs/")
@v2_bp.route("/docs")
def swagger_ui():
    """Serve the Swagger UI documentation page (public, no auth needed)."""
    return _SWAGGER_UI_HTML, 200, {"Content-Type": "text/html; charset=utf-8"}
