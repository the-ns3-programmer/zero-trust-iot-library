# Docs Repository — Lightweight Wiki with Auto-Managed Images

A single repository, two branches, zero manual image housekeeping.

- **`main`** — Markdown, `mkdocs.yml`, and automation only. Stays tiny; clones instantly.
- **`images`** — Nothing but raw image binaries. Acts as a "storage server" for `main`.

A GitHub Action does the heavy lifting: it moves new screenshots from `main`
into the `images` branch, rewrites the Markdown links to permanent
`raw.githubusercontent.com` URLs, strips the binaries back out of `main`,
deletes any image on the `images` branch that's no longer referenced
anywhere, then builds and deploys the MkDocs site to GitHub Pages.

---

## Architecture

```
                 ┌────────────────────┐
   contributor   │   feature/branch   │
   pushes to  ─▶ │  docs/*.md         │
                 │  image-files/*.png │
                 └─────────┬──────────┘
                           │ PR merge
                           ▼
                 ┌────────────────────┐
                 │       main         │──▶ triggers Action
                 │  (md + config only)│
                 └─────────┬──────────┘
                           │
             ┌─────────────┴─────────────┐
             ▼                           ▼
   ┌───────────────────┐        ┌───────────────────┐
   │   images branch   │        │   GitHub Pages    │
   │  (raw binaries)   │◀─────  │  (built site)    │
   │  orphan cleanup   │        └──────────────────┘
   └───────────────────┘
```

---

## Repository layout

```
.
├── .github/
│   └── workflows/
│       └── deploy.yml          # CI: sync images -> build -> deploy
├── docs/
│   ├── index.md
│   └── activity.md
├── scripts/
│   └── sync_images.py          # the "Transfer & Clean" automation
├── image-files/                # contributors drop screenshots here (main only)
│   └── .gitkeep
├── mkdocs.yml
├── requirements.txt
├── .gitignore
├── README.md
└── CONTRIBUTING.md
```

The `images` branch has no code at all — after the first Action run it will
contain only image files plus a small README explaining it's bot-managed.

---

## One-time setup (VSCode + GitHub)

### 1. Repo & GitHub settings
1. Create the GitHub repository (or use an existing one) and push this
   scaffold to `main`.
2. **Settings → Actions → General → Workflow permissions** → select
   **"Read and write permissions"**. This lets `GITHUB_TOKEN` push to both
   `main` and `images`.
3. **Settings → Pages** → set source to the `gh-pages` branch
   (created automatically the first time the workflow runs
   `mkdocs gh-deploy`).
4. If `main` has branch protection rules (required reviews, required
   status checks, etc.), either:
   - add an exception allowing the `github-actions[bot]` to push directly, or
   - generate a fine-grained **Personal Access Token** with `contents:write`,
     store it as a repo secret (e.g. `DEPLOY_TOKEN`), and swap the
     `actions/checkout` / push steps to use it instead of `GITHUB_TOKEN`.
5. Update `repo_url` / `repo_name` in `mkdocs.yml` to your actual
   `OWNER/REPO`.

### 2. Local machine (VSCode)
```bash
git clone https://github.com/<owner>/<repo>.git
cd <repo>
code .
```

Recommended VSCode extensions:
- **Python** (ms-python.python)
- **GitLens** (eamodio.gitlens)
- **YAML** (redhat.vscode-yaml)
- **Markdown All in One** (yzhang.markdown-all-in-one)

Set up a local environment to preview the site before pushing:
```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
mkdocs serve                     # http://127.0.0.1:8000
```

### 3. First run
The `images` branch does not need to exist beforehand — `scripts/sync_images.py`
creates it automatically as an orphan branch the first time the workflow runs.

---

## How the automation works (`scripts/sync_images.py`)

1. **Setup** — creates the `images` branch (if missing) and checks it out
   into a `git worktree` alongside the `main` working copy, so both branches
   are available in the same job without conflicting checkouts.
2. **Transfer** — every file under `image-files/` on `main` is copied into
   the `images` worktree (renamed only on a genuine filename collision with
   different content), then committed and pushed to `images`.
3. **Rewrite** — every `docs/*.md` file has its
   `image-files/<name>` links replaced with
   `https://raw.githubusercontent.com/<owner>/<repo>/images/<name>`.
4. **Clean `main`** — `image-files/` is emptied back to just `.gitkeep`,
   so no binaries linger in `main`'s history going forward.
5. **Orphan cleanup** — scans all Markdown on `main` for referenced
   `images` branch URLs, compares against what's actually stored there,
   and deletes anything no longer referenced by any page.
6. **Commit** — pushes the rewritten Markdown (and emptied `image-files/`)
   back to `main` with `[skip ci]` in the commit message, so GitHub does not
   re-trigger the same workflow in a loop.
7. **Build & deploy** — the workflow then runs `mkdocs build --strict`
   followed by `mkdocs gh-deploy`.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the contributor-facing workflow.
