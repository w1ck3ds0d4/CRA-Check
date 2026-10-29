# mcp.so draft

Status: not submitted. Do this after the Actor is published.

## What mcp.so asks for

From https://mcp.so/submit (read 2026-10-29):

- A type: MCP Server, Remote Server, MCP Client or AI Product.
- A Repository URL (marked required) and a Name.
- The page shows no description, config JSON or tag fields in the submit form; those are probably read
  from the repository or edited afterwards. Confirm in the form.
- The page offers a paid one-time option ($39) that publishes without review and adds a verified badge and
  featured placement. Free submissions go through normal review. This draft assumes the free route; the
  paid option is a decision for the maintainer.

## Fit

The only repository that describes this service is CRA-Check, which is an Action and an Actor, not an MCP
server. Submitting it as "MCP Server" would be inaccurate. "Remote Server" is the closer type, with the
Apify URL in the description, or "AI Product" if mcp.so treats the Store listing as a product page. Pick
the type the form explains best at submission time and say plainly in the description that the tool is
reached through Apify's MCP server.

## Paste

Type: Remote Server (fallback: AI Product)

Repository URL: https://github.com/w1ck3ds0d4/CRA-Check

Name: CRA Gap Check

Server URL / connect (if the form or the page asks for one): `https://mcp.apify.com?tools=APIFY-USERNAME/cra-gap-check`

One line: EU Cyber Resilience Act gap report from an SBOM, optionally signed so it can be verified later.

Description: use the long description in [README.md](README.md), then add:

> Reached through Apify's hosted MCP server. Sign in to Apify with OAuth, or send an Apify API token as a
> Bearer header. Input: `productName`, `sbomUrl` or `sbomJson`, optional `grypeUrl` or `grypeJson`, and
> `sealed` for a signed report.

Tags: eu-cra, cyber-resilience-act, sbom, compliance, supply-chain-security, evidence

Config JSON (for a page that wants one):

```json
{
  "mcpServers": {
    "cra-gap-check": {
      "url": "https://mcp.apify.com?tools=APIFY-USERNAME/cra-gap-check"
    }
  }
}
```

## File a directory would need in the repo (draft only, not added)

None found in the submit page. mcp.so reads the repository README, which already describes the Actor once
the Store link is added to the root README.

## Sources read

- https://mcp.so/submit
- https://docs.apify.com/platform/integrations/mcp
