# Activity Log

This page is an example of the contributor workflow described in
[CONTRIBUTING.md](../CONTRIBUTING.md).

## Example entry

Write your notes as normal Markdown:

```
## 2026-07-12 - Deployed staging environment
Ran the deploy script and confirmed the health checks pass.
```

## Adding a screenshot

Drop the file into `image-files/` at the repo root and link it like this:

```
![Staging dashboard](image-files/staging-dashboard.png)
```

Once this page is merged into `main`, the automation will:

1. Move `staging-dashboard.png` over to the `images` branch.
2. Rewrite the link above to point at its permanent URL there.
3. Remove the file from `main` so the branch stays lightweight.

You never need to touch the `images` branch yourself.
