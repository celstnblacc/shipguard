"""Semantic analysis engine using Tree-sitter."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import tree_sitter_javascript as ts_js
import tree_sitter_python as ts_py
from tree_sitter import Language, Parser, Tree, Node, Query, QueryCursor


class GlobalIndex:
    """Project-wide symbol and call graph index."""
    def __init__(self):
        self.symbols: dict[str, list[dict]] = {} # name -> list of locations
        self.calls: dict[str, list[str]] = {}   # caller -> list of callees

    def add_symbol(self, name: str, file_path: Path, line: int):
        self.symbols.setdefault(name, []).append({"file": str(file_path), "line": line})

    def add_call(self, caller: str, callee: str):
        self.calls.setdefault(caller, []).append(callee)


class SemanticEngine:
    """Engine for AST-based security analysis."""

    _languages: dict[str, Language] = {}
    _parsers: dict[str, Parser] = {}
    _index: GlobalIndex = GlobalIndex()

    @classmethod
    def get_index(cls) -> GlobalIndex:
        return cls._index

    @classmethod
    def get_language(cls, lang_id: str) -> Language:
        """Get or create a Tree-sitter language object."""
        if lang_id not in cls._languages:
            if lang_id == "python":
                cls._languages[lang_id] = Language(ts_py.language())
            elif lang_id == "javascript":
                cls._languages[lang_id] = Language(ts_js.language())
            else:
                raise ValueError(f"Unsupported language: {lang_id}")
        return cls._languages[lang_id]

    @classmethod
    def get_parser(cls, lang_id: str) -> Parser:
        """Get or create a Tree-sitter parser for a language."""
        if lang_id not in cls._parsers:
            parser = Parser(cls.get_language(lang_id))
            cls._parsers[lang_id] = parser
        return cls._parsers[lang_id]

    @classmethod
    def parse_file(cls, file_path: Path, content: str | None = None) -> Tree:
        """Parse a file and return its AST."""
        ext = file_path.suffix.lower()
        if ext == ".py":
            lang_id = "python"
        elif ext in (".js", ".ts", ".tsx", ".jsx"):
            lang_id = "javascript"
        else:
            raise ValueError(f"Cannot determine language for extension: {ext}")

        if content is None:
            content = file_path.read_text(errors="ignore")

        parser = cls.get_parser(lang_id)
        return parser.parse(bytes(content, "utf8"))

    @staticmethod
    def query(tree: Tree, query_scm: str) -> list[tuple[int, dict[str, list[Node]]]]:
        """Run a S-expression query on the tree using QueryCursor."""
        language = tree.language
        query = Query(language, query_scm)
        cursor = QueryCursor(query)
        return cursor.matches(tree.root_node)
