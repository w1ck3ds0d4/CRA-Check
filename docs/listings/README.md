# Directory listing drafts

Drafts of what to paste into AI-tool directories once the Apify Actor is published. Nothing here has
been submitted anywhere. Each file was written from the directory's public pages as they read on
2026-10-29; check the live form before pasting, because these pages change.

| Directory | Draft |
| --- | --- |
| Glama | [glama.md](glama.md) |
| Smithery | [smithery.md](smithery.md) |
| mcp.so | [mcp-so.md](mcp-so.md) |

## How an agent connects to the Actor

The Actor is not an MCP server of its own. Apify's hosted MCP server exposes any Actor as a tool, so
an agent connects to Apify and selects this Actor. The server URL is

```
https://mcp.apify.com?tools=APIFY-USERNAME/cra-gap-check
```

where `APIFY-USERNAME/cra-gap-check` is the Actor's Store id (placeholder until it is published). The
`tools` parameter takes Actor ids; this is the form in Apify's MCP documentation
(https://docs.apify.com/platform/integrations/mcp). Authentication is OAuth (the client opens a sign-in
page) or an `Authorization: Bearer <APIFY_TOKEN>` header. The tool's arguments are the Actor's input
schema, so the descriptions in `.actor/input_schema.json` are what the agent reads.

Client configuration (remote, OAuth):

```json
{
  "mcpServers": {
    "cra-gap-check": {
      "url": "https://mcp.apify.com?tools=APIFY-USERNAME/cra-gap-check"
    }
  }
}
```

With a token instead of OAuth:

```json
{
  "mcpServers": {
    "cra-gap-check": {
      "url": "https://mcp.apify.com?tools=APIFY-USERNAME/cra-gap-check",
      "headers": { "Authorization": "Bearer YOUR_APIFY_TOKEN" }
    }
  }
}
```

Clients without remote MCP support can use the local bridge with the same Actor id:
`npx -y @apify/actors-mcp-server --tools APIFY-USERNAME/cra-gap-check`, with `APIFY_TOKEN` set in the
environment.

## Shared copy

Name: CRA Gap Check

One line (under 100 characters): EU Cyber Resilience Act gap report from an SBOM, optionally signed so it can be verified later.

Long description:

> CRA Gap Check turns a CycloneDX or SPDX SBOM, an optional Grype vulnerability scan and a few product facts into a 14-check evidence report for the EU Cyber Resilience Act (Regulation (EU) 2024/2847): which pieces of engineering evidence are in place, which are weak and which are missing. Each check says which obligation it supports and why it passed, warned or failed. Turn on the sealed option and the report is also signed in ProofLog's evidence format, so anyone with the publisher's public key can check later that it was not altered. It is a set of engineering checks, not a conformity assessment and not legal advice. Open source engine (Apache 2.0), run on Apify and billed per report.

Tags: eu-cra, cyber-resilience-act, sbom, cyclonedx, spdx, grype, compliance, vulnerability-management, supply-chain-security, evidence

Placeholders to fill when publishing: `APIFY-USERNAME`, the Apify Store URL, the public key location.
