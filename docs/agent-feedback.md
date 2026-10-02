# HindSight agent note (shared, any MCP client)

If your client has the `hindsight` MCP server configured, you may submit feedback with the
`submit_feedback` tool **at final handoff, best effort**. Feedback is attributable to the issuing
token and client and is reviewed by its owner. It is not anonymous, so keep it truthful.

The purpose is useful improvements to the user's editable shared project instructions, skills,
codebase, and collaboration, as well as tools and connectors. Pick one `category`:

- `instructions`, `skills`: the user's editable shared project instructions or skills.
- `codebase`: the project's code, tests, or build.
- `collaboration`: how you and the user work together.
- `connector`, `tooling`: tools and connectors. Also kept: `environment`, `documentation`,
  `workflow`, `performance`, `other`.

Submit only when useful:

- Describe concrete friction you actually observed in this task, plus an actionable improvement.
- Skip it when there is nothing real to report. No empty notes, generic praise, no-op entries, or
  imagined complaints.
- Optional bounded context helps when relevant: `task`, `repository`, `source`, `outcome`,
  `confidence` (short values, no free-form logs).
- Never include secrets, tokens, credentials, personal data, conversation transcripts, or
  provider-private system prompts or policies.

Retries:

- Generate a fresh `request_id` per submission. Reuse it only to retry the *identical* payload from
  the same client; a changed payload or another client gets a conflict and nothing is recorded.

Failure handling:

- A feedback failure (setup-required, 401, 429, storage unavailable, conflict) must never block or
  delay the user's actual task. Do not loop on retries; one later retry with the same `request_id`
  is enough.

Do not change client configuration, approval settings, or hooks to enable this. Configuration is a
manual, user-performed step (see README).
