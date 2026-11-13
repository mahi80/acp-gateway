# acp-gateway — session context

## Code graph (optional, for navigation)
- Tool: [graphify](https://github.com/Graphify-Labs/graphify) (PyPI package `graphifyy`, note the double y). It is a developer aid, not a dependency of this repo.
- At the start of a session, if `graphify` is installed: `GRAPHIFY_BACKEND=none graphify update .` — code-only, local, no LLM, under 30 s. Output goes to `graphify-out/` (git-ignored; never commit it).
- Then `graphify explain "<symbol>"` and `graphify path "<A>" "<B>"` for structure and direct calls; `graphify-out/GRAPH_REPORT.md` for the overview.
- It misses calls made through an object (`self._sink.method()`), so confirm callers with grep before changing a function. Do not enable its strict mode or its Read/Grep hooks.
- Keep `GRAPHIFY_BACKEND=none` (or `ollama`): any other backend sends docs and PDFs to an external LLM.
