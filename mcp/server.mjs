// Minimal MCP server to access Auth API with a PAT (MCP token)
// Requires: npm i @modelcontextprotocol/sdk undici

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { fetch } from "undici";

const BASE_URL = (process.env.AUTH_API_BASE_URL || "http://localhost:8080").replace(/\/$/, "");
const PAT = process.env.AUTH_API_PAT || "";

const server = new Server(
  { name: "auth-api-mcp", version: "0.1.0", description: "MCP server for Auth Fast API" },
  { capabilities: { tools: {}, resources: {} } }
);

server.addTool(
  {
    name: "auth_api.request",
    description:
      "Faz uma chamada HTTP à Auth API injetando Authorization: Bearer <PAT>. Informe path relativo (ex.: /admin), método e parâmetros.",
    inputSchema: {
      type: "object",
      properties: {
        method: { type: "string", enum: ["GET", "POST", "PUT", "PATCH", "DELETE"] },
        path: { type: "string", description: "Caminho iniciado por /. Use prefixo /api se necessário (Vercel)." },
        query: { type: "object", additionalProperties: { type: ["string", "number", "boolean"] } },
        headers: { type: "object", additionalProperties: { type: "string" } },
        body: { description: "Objeto JSON ou string para o corpo da requisição", anyOf: [{ type: "object" }, { type: "string" }] },
        contentType: { type: "string", description: "Content-Type a enviar quando houver body (default application/json)" }
      },
      required: ["method", "path"],
      additionalProperties: false
    }
  },
  async (args) => {
    if (!PAT) {
      return {
        content: [
          {
            type: "text",
            text: "Erro: defina AUTH_API_PAT no ambiente antes de usar a ferramenta."
          }
        ]
      };
    }

    const method = String(args.method || "GET").toUpperCase();
    let path = String(args.path || "/");
    if (!path.startsWith("/")) path = "/" + path;

    const url = new URL(BASE_URL + path);
    if (args.query && typeof args.query === "object") {
      for (const [k, v] of Object.entries(args.query)) {
        if (v === undefined || v === null) continue;
        url.searchParams.set(k, String(v));
      }
    }

    const headers = new Headers({ Accept: "application/json", Authorization: `Bearer ${PAT}` });
    if (args.headers && typeof args.headers === "object") {
      for (const [k, v] of Object.entries(args.headers)) {
        if (typeof v === "string") headers.set(k, v);
      }
    }

    let body;
    if (args.body !== undefined) {
      const ct = args.contentType || headers.get("Content-Type") || "application/json";
      headers.set("Content-Type", ct);
      if (ct.includes("application/json") && typeof args.body === "object") {
        body = JSON.stringify(args.body);
      } else {
        body = typeof args.body === "string" ? args.body : JSON.stringify(args.body);
      }
    }

    const res = await fetch(url, { method, headers, body });
    const text = await res.text();
    let parsed;
    const ct = res.headers.get("content-type") || "";
    if (ct.includes("application/json")) {
      try { parsed = JSON.parse(text); } catch { parsed = text; }
    } else {
      parsed = text;
    }

    const out = {
      ok: res.ok,
      status: res.status,
      statusText: res.statusText,
      url: url.toString(),
      headers: Object.fromEntries(res.headers),
      body: parsed
    };

    return { content: [{ type: "text", text: JSON.stringify(out, null, 2) }] };
  }
);

await server.connect(new StdioServerTransport());

