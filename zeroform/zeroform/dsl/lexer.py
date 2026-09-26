"""
ZEROFORM Reality DSL — Lexer
=============================

Tokenizes ``.zf`` Reality DSL source into a flat token stream consumed
by :mod:`zeroform.dsl.parser`. The DSL grammar (informally) is::

    module      := import* block*
    import      := "import" STRING
    block       := IDENT STRING? "{" body "}"
    body        := (attribute | block)*
    attribute   := IDENT ":" value
    value       := STRING | NUMBER | BOOL | list | block
    list        := "[" (value ("," value)*)? "]"

Comments start with ``#`` or ``//`` and run to end of line.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, auto
from typing import List


class TokenType(Enum):
    IDENT = auto()
    STRING = auto()
    NUMBER = auto()
    BOOL = auto()
    COLON = auto()
    COMMA = auto()
    LBRACE = auto()
    RBRACE = auto()
    LBRACKET = auto()
    RBRACKET = auto()
    AT = auto()
    DOT = auto()
    EOF = auto()


@dataclass(frozen=True)
class Token:
    type: TokenType
    value: object
    line: int
    col: int

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"Token({self.type.name}, {self.value!r}, {self.line}:{self.col})"


class LexError(Exception):
    def __init__(self, message: str, line: int, col: int):
        super().__init__(f"Lex error at {line}:{col}: {message}")
        self.line = line
        self.col = col


_KEYWORDS_BOOL = {"true": True, "false": False}

_SINGLE_CHAR_TOKENS = {
    "{": TokenType.LBRACE,
    "}": TokenType.RBRACE,
    "[": TokenType.LBRACKET,
    "]": TokenType.RBRACKET,
    ":": TokenType.COLON,
    ",": TokenType.COMMA,
    "@": TokenType.AT,
    ".": TokenType.DOT,
}


class Lexer:
    """Hand written scanner; no external dependency required."""

    def __init__(self, source: str):
        self.source = source
        self.pos = 0
        self.line = 1
        self.col = 1

    def _peek(self, offset: int = 0) -> str:
        idx = self.pos + offset
        return self.source[idx] if idx < len(self.source) else ""

    def _advance(self) -> str:
        ch = self.source[self.pos]
        self.pos += 1
        if ch == "\n":
            self.line += 1
            self.col = 1
        else:
            self.col += 1
        return ch

    def _skip_ignorable(self) -> None:
        while self.pos < len(self.source):
            ch = self._peek()
            if ch in " \t\r\n":
                self._advance()
            elif ch == "#" or (ch == "/" and self._peek(1) == "/"):
                while self.pos < len(self.source) and self._peek() != "\n":
                    self._advance()
            elif ch == "/" and self._peek(1) == "*":
                self._advance()
                self._advance()
                while self.pos < len(self.source) and not (
                    self._peek() == "*" and self._peek(1) == "/"
                ):
                    self._advance()
                self._advance()
                self._advance()
            else:
                break

    def tokenize(self) -> List[Token]:
        tokens: List[Token] = []
        while True:
            self._skip_ignorable()
            if self.pos >= len(self.source):
                tokens.append(Token(TokenType.EOF, None, self.line, self.col))
                break
            start_line, start_col = self.line, self.col
            ch = self._peek()

            if ch == '"':
                tokens.append(self._read_string())
                continue

            if ch.isdigit() or (ch == "-" and self._peek(1).isdigit()):
                tokens.append(self._read_number())
                continue

            if ch.isalpha() or ch == "_":
                tokens.append(self._read_ident_or_bool())
                continue

            if ch in _SINGLE_CHAR_TOKENS:
                self._advance()
                tokens.append(Token(_SINGLE_CHAR_TOKENS[ch], ch, start_line, start_col))
                continue

            raise LexError(f"unexpected character {ch!r}", start_line, start_col)
        return tokens

    def _read_string(self) -> Token:
        start_line, start_col = self.line, self.col
        self._advance()  # opening quote
        buf = []
        while True:
            if self.pos >= len(self.source):
                raise LexError("unterminated string literal", start_line, start_col)
            ch = self._advance()
            if ch == '"':
                break
            if ch == "\\":
                esc = self._advance()
                mapping = {"n": "\n", "t": "\t", '"': '"', "\\": "\\"}
                buf.append(mapping.get(esc, esc))
            else:
                buf.append(ch)
        return Token(TokenType.STRING, "".join(buf), start_line, start_col)

    def _read_number(self) -> Token:
        start_line, start_col = self.line, self.col
        buf = []
        if self._peek() == "-":
            buf.append(self._advance())
        while self._peek().isdigit():
            buf.append(self._advance())
        if self._peek() == "." and self._peek(1).isdigit():
            buf.append(self._advance())
            while self._peek().isdigit():
                buf.append(self._advance())
            value: object = float("".join(buf))
        else:
            value = int("".join(buf))
        return Token(TokenType.NUMBER, value, start_line, start_col)

    def _read_ident_or_bool(self) -> Token:
        start_line, start_col = self.line, self.col
        buf = []
        while self._peek().isalnum() or self._peek() in "_-":
            buf.append(self._advance())
        text = "".join(buf)
        if text in _KEYWORDS_BOOL:
            return Token(TokenType.BOOL, _KEYWORDS_BOOL[text], start_line, start_col)
        return Token(TokenType.IDENT, text, start_line, start_col)


def tokenize(source: str) -> List[Token]:
    return Lexer(source).tokenize()
