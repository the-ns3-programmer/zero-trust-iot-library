#!/usr/bin/env python3
"""
sync_images.py

Runs inside the GitHub Action on the `main` branch. It:

  1. Finds new images dropped by contributors into image-files/ on main.
  2. Moves them into the `images` branch (used purely as binary storage).
  3. Rewrites Markdown links in docs/*.md to point at the images branch's
     raw.githubusercontent.com URL instead of the local image-files/ path.
  4. Deletes the now-empty image-files/ content from main, keeping the
     branch tiny.
  5. Scans all Markdown on main for referenced images, and deletes any
     file on the images branch that is no longer referenced anywhere
     (orphan cleanup) -- so nobody ever has to clean up old screenshots
     by hand.

Uses a git worktree so main and images can be manipulated side by side
in a single job without two separate checkouts.
"""

import hashlib
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

REPO = os.environ.get("GITHUB_REPOSITORY")  # "owner/repo", set by Actions
IMAGES_BRANCH = "images"
IMAGE_SRC_DIR = Path("image-files")
DOCS_DIR = Path("docs")
WORKTREE_DIR = Path("../images-branch-worktree").resolve()


def run(cmd, cwd=None, check=True):
    print(f"$ {' '.join(cmd)}  (cwd={cwd or os.getcwd()})")
    result = subprocess.run(cmd, cwd=cwd, text=True, capture_output=True)
    if result.stdout.strip():
        print(result.stdout)
    if result.stderr.strip():
        print(result.stderr)
    if check and result.returncode != 0:
        raise RuntimeError(f"Command failed: {' '.join(cmd)}\n{result.stderr}")
    return result


def git(*args, cwd=None, check=True):
    return run(["git", *args], cwd=cwd, check=check)


def raw_url(filename: str) -> str:
    return f"https://raw.githubusercontent.com/{REPO}/{IMAGES_BRANCH}/{filename}"


def ensure_images_branch_exists():
    """Create the images branch as an orphan branch if it doesn't exist yet."""
    result = git("ls-remote", "--exit-code", "--heads", "origin", IMAGES_BRANCH, check=False)
    if result.returncode != 0:
        print(f"Remote branch '{IMAGES_BRANCH}' not found. Creating it as an orphan branch.")
        git("checkout", "--orphan", IMAGES_BRANCH)
        git("rm", "-rf", ".", check=False)
        Path("README.md").write_text(
            "# Images Storage Branch\n\n"
            "This branch stores raw image assets referenced by documentation on `main`.\n"
            "It is fully managed by CI automation (scripts/sync_images.py). "
            "Do not edit it by hand.\n"
        )
        git("add", "README.md")
        git("commit", "-m", "chore: initialize images branch [skip ci]")
        git("push", "origin", IMAGES_BRANCH)
        git("checkout", "main")


def setup_worktree():
    ensure_images_branch_exists()
    git("fetch", "origin", IMAGES_BRANCH)
    if WORKTREE_DIR.exists():
        shutil.rmtree(WORKTREE_DIR)
    git("worktree", "add", str(WORKTREE_DIR), IMAGES_BRANCH)


def unique_target_name(images_root: Path, filename: str, content: bytes) -> str:
    """Avoid silently overwriting a different file that happens to share a name."""
    target = images_root / filename
    if not target.exists():
        return filename
    if target.read_bytes() == content:
        return filename  # identical content, safe to reuse the name
    stem, ext = os.path.splitext(filename)
    digest = hashlib.sha1(content).hexdigest()[:8]
    return f"{stem}-{digest}{ext}"


def transfer_images() -> dict:
    """Move image-files/* from main into the images branch worktree."""
    if not IMAGE_SRC_DIR.exists():
        print("No image-files/ directory found. Nothing to transfer.")
        return {}

    images = [p for p in IMAGE_SRC_DIR.rglob("*") if p.is_file() and p.name != ".gitkeep"]
    if not images:
        print("image-files/ is empty. Nothing to transfer.")
        return {}

    mapping = {}  # "image-files/foo.png" -> raw.githubusercontent.com URL
    for img in images:
        content = img.read_bytes()
        final_name = unique_target_name(WORKTREE_DIR, img.name, content)
        (WORKTREE_DIR / final_name).write_bytes(content)
        old_link = img.as_posix()
        mapping[old_link] = raw_url(final_name)
        print(f"Staged {old_link} -> {mapping[old_link]}")

    git("add", "-A", cwd=str(WORKTREE_DIR))
    status = git("status", "--porcelain", cwd=str(WORKTREE_DIR))
    if status.stdout.strip():
        git("commit", "-m", "chore: add new images from main [skip ci]", cwd=str(WORKTREE_DIR))
        git("push", "origin", IMAGES_BRANCH, cwd=str(WORKTREE_DIR))
    else:
        print("No new image content to commit on images branch.")

    return mapping


def rewrite_links(mapping: dict):
    if not mapping:
        return
    for md in DOCS_DIR.rglob("*.md"):
        text = md.read_text(encoding="utf-8")
        original = text
        for old_link, new_url in mapping.items():
            text = text.replace(old_link, new_url)
        if text != original:
            md.write_text(text, encoding="utf-8")
            print(f"Rewrote links in {md}")


def clean_main_image_files():
    if IMAGE_SRC_DIR.exists():
        shutil.rmtree(IMAGE_SRC_DIR)
        IMAGE_SRC_DIR.mkdir()
        (IMAGE_SRC_DIR / ".gitkeep").touch()
        print("Cleared image-files/ on main (kept as an empty folder for the next contributor).")


def find_referenced_images() -> set:
    pattern = re.compile(
        rf"https://raw\.githubusercontent\.com/{re.escape(REPO)}/{IMAGES_BRANCH}/([^\s\)\"']+)"
    )
    referenced = set()
    for md in DOCS_DIR.rglob("*.md"):
        text = md.read_text(encoding="utf-8")
        referenced.update(match.group(1) for match in pattern.finditer(text))
    return referenced


def cleanup_orphans(referenced: set):
    all_files = [
        p.name for p in WORKTREE_DIR.iterdir()
        if p.is_file() and p.name != "README.md" and not p.name.startswith(".git")
    ]
    orphans = [f for f in all_files if f not in referenced]
    if not orphans:
        print("No orphaned images found.")
        return

    for f in orphans:
        (WORKTREE_DIR / f).unlink()
        print(f"Deleted orphaned image: {f}")

    git("add", "-A", cwd=str(WORKTREE_DIR))
    status = git("status", "--porcelain", cwd=str(WORKTREE_DIR))
    if status.stdout.strip():
        git("commit", "-m", "chore: remove orphaned images [skip ci]", cwd=str(WORKTREE_DIR))
        git("push", "origin", IMAGES_BRANCH, cwd=str(WORKTREE_DIR))


def commit_main_changes():
    git("add", "-A")
    status = git("status", "--porcelain")
    if status.stdout.strip():
        git("commit", "-m", "chore: sync images and rewrite links [skip ci]")
        git("push", "origin", "main")
    else:
        print("No changes to commit on main.")


def teardown_worktree():
    if WORKTREE_DIR.exists():
        git("worktree", "remove", "--force", str(WORKTREE_DIR), check=False)


def main():
    if not REPO:
        print("GITHUB_REPOSITORY is not set. This script is meant to run inside GitHub Actions.")
        sys.exit(1)

    git("config", "user.name", "docs-bot", check=False)
    git("config", "user.email", "docs-bot@users.noreply.github.com", check=False)

    setup_worktree()
    mapping = transfer_images()
    rewrite_links(mapping)
    clean_main_image_files()

    referenced = find_referenced_images()
    cleanup_orphans(referenced)

    commit_main_changes()
    teardown_worktree()


if __name__ == "__main__":
    main()
