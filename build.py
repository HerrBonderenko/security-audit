#!/usr/bin/env python3
"""Собирает dist/<скилл>.zip (загрузка в claude.ai, раздел Skills в настройках) и dist/<скилл>.skill
(тот же zip — кнопка «Save skill» в чате) для каждого скилла из skills/. Запуск: python build.py"""
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DIST = ROOT / "dist"
SKIP = {"__pycache__", ".DS_Store"}


def build():
    DIST.mkdir(exist_ok=True)
    for skill in sorted(p for p in (ROOT / "skills").iterdir() if (p / "SKILL.md").exists()):
        files = [p for p in sorted(skill.rglob("*")) if p.is_file()
                 and not any(part in SKIP for part in p.parts) and p.suffix != ".pyc"]
        for ext in (".zip", ".skill"):
            out = DIST / f"{skill.name}{ext}"
            with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
                for p in files:
                    z.write(p, Path(skill.name) / p.relative_to(skill))
            print(f"{out.relative_to(ROOT)}: {len(files)} файлов")


if __name__ == "__main__":
    build()
