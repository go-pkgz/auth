---
worth: yes
where: AGENTS.md
added: 2026-11-28
---
# Claude Code skips AGENTS.md under the go-pkgz parent CLAUDE.md

Claude Code reads a repo's AGENTS.md only when no CLAUDE.md exists in the working directory or above
(code.claude.com/docs/en/memory.md, "AGENTS.md"). In the go-pkgz monorepo checkout, `go-pkgz/CLAUDE.md`
sits above `auth/`, so a session in auth loads only the monorepo file and none of auth's own rules. Found
while reviewing go-pkgz/rest PR #59, which moves rest to the same layout.

Fix: add `auth/CLAUDE.md` containing `@AGENTS.md`, or set Claude Code's project-instructions option to
`claude-md-and-agents-md`, which loads both in every repo.
