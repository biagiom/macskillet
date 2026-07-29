#!/usr/bin/env python3
"""
install-skill.py — Install macskillet Claude Code skill into ~/.claude/skills/

Creates symlinks on macOS/Linux. Falls back to copies on Windows when symlink
privilege is unavailable (requires Developer Mode or admin rights on Windows).
"""

import shutil
import sys
from pathlib import Path

REPO = Path(__file__).parent.resolve()
SKILLS_DIR = Path.home() / ".claude" / "skills"

# (destination relative to SKILLS_DIR, source in repo)
LINKS: list[tuple[Path, Path]] = [
    (Path("macskillet") / "SKILL.md",  REPO / "SKILL.md"),
    (Path("macskillet-modes"),          REPO / "skills" / "macskillet-modes"),
    (Path("macskillet-tools"),          REPO / "skills" / "macskillet-tools"),
    (Path("macskillet-risk-signals"),   REPO / "skills" / "macskillet-risk-signals"),
]


def _remove(path: Path) -> None:
    if path.is_symlink() or path.is_file():
        path.unlink()
    elif path.is_dir():
        shutil.rmtree(path)


def install() -> None:
    SKILLS_DIR.mkdir(parents=True, exist_ok=True)

    for dest_rel, src in LINKS:
        dest = SKILLS_DIR / dest_rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        _remove(dest)

        try:
            dest.symlink_to(src)
            print(f"  symlink  {dest_rel}")
        except (OSError, NotImplementedError):
            # Windows without symlink privilege — copy instead
            if src.is_dir():
                shutil.copytree(src, dest)
            else:
                shutil.copy2(src, dest)
            print(f"  copied   {dest_rel}  (no symlink privilege — update manually after pulling)")

    print(f"\nmacskillet skill installed -> {SKILLS_DIR}")
    print("In Claude Code: ask to analyze a .app or Mach-O binary — skill triggers automatically.")


if __name__ == "__main__":
    install()
