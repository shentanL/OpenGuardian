"""知识库语义向量检索 —— 将 GLOSSARY 条目转为 TF-IDF 向量做语义匹配。

零依赖（纯标准库），替代手写的 _word_overlap() bigram 匹配。
"""
from __future__ import annotations

import math
import re
from typing import Optional


class TFIDFIndex:
    """轻量 TF-IDF 索引 —— 适合 ~1000 条文档的本地检索。"""

    def __init__(self):
        self._docs: list[str] = []
        self._doc_texts: list[str] = []
        self._idf: dict[str, float] = {}
        self._tfidf_vectors: list[dict[str, float]] = []
        self._built = False

    @staticmethod
    def _tokenize(text: str) -> list[str]:
        """中文按 1-2 字、英文按词分词。"""
        tokens: list[str] = []
        # 英文词
        eng_words = re.findall(r"[a-zA-Z0-9]+", text.lower())
        tokens.extend(eng_words)
        # 中文 bigram + 单字
        chinese = re.sub(r"[a-zA-Z0-9\s]", "", text)
        for i in range(len(chinese) - 1):
            tokens.append(chinese[i : i + 2])
        for c in chinese:
            tokens.append(c)
        return tokens

    def add(self, doc_id: str, text: str) -> None:
        self._docs.append(doc_id)
        self._doc_texts.append(text)
        self._built = False

    def build(self) -> None:
        """构建 TF-IDF 索引。"""
        doc_count = len(self._docs)
        if doc_count == 0:
            self._built = True
            return

        # TF
        doc_tokens: list[dict[str, int]] = []
        df: dict[str, int] = {}  # document frequency
        for text in self._doc_texts:
            tokens = self._tokenize(text)
            tf: dict[str, int] = {}
            seen: set[str] = set()
            for t in tokens:
                tf[t] = tf.get(t, 0) + 1
                if t not in seen:
                    df[t] = df.get(t, 0) + 1
                    seen.add(t)
            doc_tokens.append(tf)

        # IDF
        self._idf = {
            t: math.log((doc_count + 1) / (freq + 1)) + 1.0
            for t, freq in df.items()
        }

        # TF-IDF vectors
        self._tfidf_vectors = []
        for tf in doc_tokens:
            vec: dict[str, float] = {}
            for t, count in tf.items():
                vec[t] = count * self._idf.get(t, 0)
            self._tfidf_vectors.append(vec)

        self._built = True

    def _ensure_built(self) -> None:
        if not self._built:
            self.build()

    def _cosine(self, a: dict[str, float], b: dict[str, float]) -> float:
        """余弦相似度。"""
        dot = sum(a.get(k, 0) * b.get(k, 0) for k in set(a) | set(b) if k in a and k in b)
        norm_a = math.sqrt(sum(v * v for v in a.values()))
        norm_b = math.sqrt(sum(v * v for v in b.values()))
        if norm_a == 0 or norm_b == 0:
            return 0.0
        return dot / (norm_a * norm_b)

    def search(self, query: str, top_k: int = 5) -> list[tuple[str, float, str]]:
        """语义搜索，返回 [(doc_id, score, text), ...]。"""
        self._ensure_built()
        if not self._tfidf_vectors:
            return []

        query_tokens = self._tokenize(query)
        query_tf: dict[str, int] = {}
        for t in query_tokens:
            query_tf[t] = query_tf.get(t, 0) + 1
        query_vec = {t: count * self._idf.get(t, 0) for t, count in query_tf.items()}

        scores = [(self._docs[i], self._cosine(query_vec, vec), self._doc_texts[i])
                  for i, vec in enumerate(self._tfidf_vectors)]
        scores.sort(key=lambda x: x[1], reverse=True)
        return [(d, s, t) for d, s, t in scores if s > 0.05][:top_k]


# 全局索引
_index: Optional[TFIDFIndex] = None


def get_search_index() -> TFIDFIndex:
    global _index
    if _index is None:
        _index = TFIDFIndex()
        from .glossary import GLOSSARY

        for key, entry in GLOSSARY.items():
            main_term = key.split("|")[0]
            text = f"{main_term} {entry.get('plain', '')} {entry.get('advice', '')}"
            _index.add(main_term, text)
        # 也加入案例库
        try:
            from ..agents.educator import CASES
            for key, case in CASES.items():
                text = f"{key} {case.get('scenario', '')} {case.get('explain', '')}"
                _index.add(f"case:{key}", text)
        except Exception:
            pass
        _index.build()
    return _index


def semantic_search(query: str, top_k: int = 5) -> list[dict]:
    """语义搜索知识库，返回相关条目列表。"""
    results = get_search_index().search(query, top_k)
    return [{"term": doc_id, "score": round(score, 3), "text": text[:200]}
            for doc_id, score, text in results]
