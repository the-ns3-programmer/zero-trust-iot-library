# Contributing

You only ever need to touch the `main` branch's content — never the
`images` branch. The bot handles storage and cleanup for you.

## 1. Clone
```bash
git clone --branch main https://github.com/<owner>/<repo>.git
cd <repo>
```

## 2. Create your feature branch
```bash
git checkout -b feature/my-update
```

## 3. Write your content
- Edit or create pages under `docs/`, e.g. `docs/activity.md`.
- Drop any screenshots into `image-files/` at the repo root.

## 4. Link images
Reference them with a relative path, exactly as they sit locally:
```markdown
![Login screen](image-files/login-screen.png)
```

## 5. Push
```bash
git add .
git commit -m "Add notes on the new login flow"
git push -u origin feature/my-update
```

Open a pull request into `main`. Once it's merged:
- your images are moved to permanent storage on the `images` branch,
- the links in your Markdown are rewritten automatically,
- `image-files/` is cleared back out on `main`,
- any screenshot that's no longer referenced anywhere is deleted
  automatically — you never have to clean up after yourself,
- the site rebuilds and redeploys.

That's it — no manual asset management, ever.
