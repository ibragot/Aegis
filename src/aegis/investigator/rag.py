"""Retrieval-Augmented Generation (RAG): find the playbook sections relevant to an incident.

Pipeline:
1. **Chunk** every markdown file in `knowledge/` at `##` headings. One chunk =
   one focused topic ("Containment", "T1098.003 Additional Cloud Roles", ...).
2. **Index** the chunks with TF-IDF (word uni+bi-grams). TF-IDF is a sparse,
   keyword-based vector space - perfect for security text full of exact terms
   like `AttachRolePolicy` or `T1110.003`, and it needs no GPU or external API.
3. **Query** with text built from the incident (rule names, ATT&CK techniques,
   actions) and rank chunks by cosine similarity, boosted when a chunk mentions
   one of the incident's technique ids. Results are diversified (max 2 per file).

Swapping TF-IDF for dense embeddings (e.g. pgvector + an embedding model) only
changes `Retriever.search` - the rest of the investigator is unaffected.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import linear_kernel

_TECH_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


@dataclass
class Chunk:
    id: str
    doc: str
    title: str
    text: str

    @property
    def techniques(self) -> set[str]:
        return set(_TECH_RE.findall(self.text))


def _slug(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")


def chunk_markdown(path: Path, root: Path) -> list[Chunk]:
    text = path.read_text()
    rel = str(path.relative_to(root))
    doc_title = next((ln[2:].strip() for ln in text.splitlines() if ln.startswith("# ")), path.stem)
    chunks: list[Chunk] = []
    current_title, buf = "Overview", []
    for line in text.splitlines():
        if line.startswith("## "):
            if "".join(buf).strip():
                chunks.append(Chunk(f"{rel}#{_slug(current_title)}", rel, f"{doc_title} - {current_title}",
                                    "\n".join(buf).strip()))
            current_title, buf = line[3:].strip(), []
        elif not line.startswith("# "):
            buf.append(line)
    if "".join(buf).strip():
        chunks.append(Chunk(f"{rel}#{_slug(current_title)}", rel, f"{doc_title} - {current_title}", "\n".join(buf).strip()))
    return chunks


class Retriever:
    def __init__(self, knowledge_dir: Path):
        self.chunks: list[Chunk] = []
        for path in sorted(knowledge_dir.rglob("*.md")):
            self.chunks.extend(chunk_markdown(path, knowledge_dir))
        if not self.chunks:
            raise ValueError(f"no knowledge documents in {knowledge_dir}")
        self.vectorizer = TfidfVectorizer(ngram_range=(1, 2), sublinear_tf=True, stop_words="english",
                                          token_pattern=r"(?u)\b[\w\.\-/:]{2,}\b")
        self.matrix = self.vectorizer.fit_transform([f"{c.title}\n{c.text}" for c in self.chunks])

    def search(self, query: str, k: int = 6, techniques: set[str] | None = None, per_doc: int = 2) -> list[dict]:
        sims = linear_kernel(self.vectorizer.transform([query]), self.matrix).ravel()
        techniques = techniques or set()
        scored = []
        for i, c in enumerate(self.chunks):
            boost = 0.15 * len(c.techniques & techniques) if techniques else 0.0
            # parent technique match (T1110 for T1110.003) counts a little too
            boost += 0.05 * len({t.split(".")[0] for t in c.techniques} & {t.split(".")[0] for t in techniques})
            scored.append((sims[i] + boost, i))
        scored.sort(reverse=True)
        out, per = [], {}
        for score, i in scored:
            c = self.chunks[i]
            if per.get(c.doc, 0) >= per_doc or score <= 0:
                continue
            per[c.doc] = per.get(c.doc, 0) + 1
            out.append({"id": c.id, "title": c.title, "score": round(float(score), 3), "text": c.text})
            if len(out) >= k:
                break
        return out
