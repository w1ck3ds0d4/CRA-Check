# Smithery draft

Status: not submitted. Do this after the Actor is published.

## What Smithery asks for

From https://smithery.ai/docs/build/publish (read 2026-10-29):

- Two ways to publish. A hosted server is a public HTTPS URL that speaks Streamable HTTP, which
  Smithery's gateway proxies to. A local server is a pre-built `.mcpb` bundle.
- Hosted publishing: go to https://smithery.ai/new, enter the URL and complete the flow, or use the CLI:
  `smithery mcp publish "https://your-server.com/mcp" -n @your-org/your-server`. An optional
  `--config-schema` takes a JSON Schema string.
- Smithery scans the URL to read the server's tools. A public server is scanned automatically. A server that
  needs authentication must be authenticated for the scan. If the scan fails, the server can host a card at
  `/.well-known/mcp/server-card.json` with `serverInfo` (name and version).
- The docs do not list description, tags or icon fields. Those are probably set on the server page after
  publishing; confirm in the flow.
- After publishing, Settings, Verification has a checklist for official vendors.

## Fit and risks

The URL is Apify's, not ours. Smithery would scan `mcp.apify.com` with the Actor pre-selected, which needs
an Apify sign-in for the scan, and we cannot host a server card on Apify's domain. Apify's own server is
already listed on Smithery (as `@apify/actors-mcp-server`). It is unclear whether Smithery accepts a
second entry for the same host with a different `tools` parameter. If it does not, the useful result is
still a one-line mention in the Actor's README. Do not pay for or request anything beyond the free flow.

## Paste

Name (the `-n` value): `@w1ck3ds0d4/cra-gap-check` (use the Smithery namespace you own; it must be claimed
in Smithery first)

URL: `https://mcp.apify.com?tools=APIFY-USERNAME/cra-gap-check`

Command, to run yourself when ready (the Actor must be published and you must be signed in to Smithery):

```
smithery mcp publish "https://mcp.apify.com?tools=APIFY-USERNAME/cra-gap-check" -n @w1ck3ds0d4/cra-gap-check
```

Display name: CRA Gap Check

One line: EU Cyber Resilience Act gap report from an SBOM, optionally signed so it can be verified later.

Description: use the long description in [README.md](README.md).

Tags: eu-cra, cyber-resilience-act, sbom, compliance, supply-chain-security

Authentication note for the description: sign in to Apify with OAuth when the client asks, or send an
Apify API token as a Bearer header.

## Connect

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

None. Smithery's hosted path needs no file in this repository. The older `smithery.yaml` is for servers
Smithery builds from a repository, which does not apply, and the docs page read does not mention it.

## Sources read

- https://smithery.ai/docs/build/publish
- https://docs.apify.com/platform/integrations/mcp
