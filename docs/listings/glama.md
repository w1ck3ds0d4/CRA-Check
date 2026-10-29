# Glama draft

Status: not submitted. Do this after the Actor is published and a sealed run has worked end to end.

## What Glama asks for

From Glama's public pages (the "Add Server" form itself needs a Glama sign-in and is rendered in the
browser, so its exact fields were not readable; confirm them in the form):

- Glama lists two kinds of entry. Repository-based servers are found from a GitHub repository and claimed
  by adding a `glama.json` file to the repository root (a `$schema` and a `maintainers` list of GitHub
  usernames), then running the Claim ownership flow. Remote connectors are claimed from the listing page by
  signing in and verifying with a GitHub identity, an HTTP challenge file at `/.well-known/glama.json` on
  the server's domain, or a DNS record.
- Once claimed, the owner can edit the name, description and other attributes.
- Listings show a license, quality and maintenance grades and a health check, so a remote entry needs a
  server that answers.

## Which entry fits

This Actor is reached through Apify's hosted MCP server, which Apify already lists on Glama. The only
sensible entry for this project is a remote connector pointing at the Apify URL below. A repository entry
would not fit, because the CRA-Check repository is a GitHub Action and an Actor, not an MCP server.
Adding a `glama.json` to this repository would claim a listing that does not exist, so do not add one.

Ownership of `mcp.apify.com` cannot be proven by the HTTP or DNS methods, and the GitHub-identity route
belongs to the Apify listing. It is therefore unclear whether Glama will accept a third party's pre-selected
Apify URL as a separate remote entry. Treat this listing as "try it and see", and if Glama declines, the
fallback is to mention the Actor in the Store README only.

## Paste

Entry type: remote server / connector

Name: CRA Gap Check

URL: `https://mcp.apify.com?tools=APIFY-USERNAME/cra-gap-check`

Transport: Streamable HTTP

Authentication: OAuth through Apify, or `Authorization: Bearer <APIFY_TOKEN>`

One line: EU Cyber Resilience Act gap report from an SBOM, optionally signed so it can be verified later.

Description: use the long description in [README.md](README.md).

Tags / categories: Security, Compliance, Developer Tools, Supply Chain (use the closest of Glama's own
category names; the tags in README.md are the search terms)

Repository link (for the license and source): https://github.com/w1ck3ds0d4/CRA-Check (Apache 2.0)

## Connect (to put in the description or README field)

```json
{
  "mcpServers": {
    "cra-gap-check": {
      "url": "https://mcp.apify.com?tools=APIFY-USERNAME/cra-gap-check"
    }
  }
}
```

Tool input: `productName` (required), `sbomUrl` or `sbomJson` (one of them), optional `grypeUrl` or
`grypeJson`, product facts, and `sealed` (boolean).

## File a directory would need in the repo (draft only, not added)

Only for a repository-based entry, which is not recommended above:

```json
{
  "$schema": "https://glama.ai/mcp/schemas/server.json",
  "maintainers": ["w1ck3ds0d4"]
}
```

## Sources read

- https://glama.ai/blog/2025-07-08-what-is-glamajson
- https://glama.ai/mcp/servers (Add Server button, no steps on the page)
- https://glama.ai/mcp/remote-servers/com.postman/postman-mcp-server (a remote connector listing and its claim flow)
- https://docs.apify.com/platform/integrations/mcp
