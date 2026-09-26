"""
ZEROFORM Reality DSL — Parser
===============================

Recursive-descent parser turning a token stream into a
:class:`zeroform.dsl.ast_nodes.Module`. Supports nested blocks (used
e.g. for inline ``condition { ... }`` bodies inside a ``policy``
block), lists, scalars and ``import "path"`` statements for splitting
a large Reality Model across multiple files / reusable components.
"""

from __future__ import annotations

from typing import List, Optional

from .ast_nodes import Block, Module, Value
from .lexer import Token, TokenType, tokenize


class ParseError(Exception):
    def __init__(self, message: str, token: Token):
        super().__init__(f"Parse error at {token.line}:{token.col}: {message}")
        self.token = token


class Parser:
    def __init__(self, tokens: List[Token], source_name: str = "<memory>"):
        self.tokens = tokens
        self.pos = 0
        self.source_name = source_name

    # -- token helpers -----------------------------------------------
    def _peek(self, offset: int = 0) -> Token:
        idx = min(self.pos + offset, len(self.tokens) - 1)
        return self.tokens[idx]

    def _advance(self) -> Token:
        tok = self.tokens[self.pos]
        if self.pos < len(self.tokens) - 1:
            self.pos += 1
        return tok

    def _expect(self, ttype: TokenType) -> Token:
        tok = self._peek()
        if tok.type != ttype:
            raise ParseError(f"expected {ttype.name}, got {tok.type.name} ({tok.value!r})", tok)
        return self._advance()

    def _match(self, ttype: TokenType) -> bool:
        if self._peek().type == ttype:
            self._advance()
            return True
        return False

    # -- grammar -------------------------------------------------------
    def parse_module(self) -> Module:
        module = Module(source_name=self.source_name)
        while self._peek().type != TokenType.EOF:
            if self._peek().type == TokenType.IDENT and self._peek().value == "import":
                self._advance()
                path_tok = self._expect(TokenType.STRING)
                module.imports.append(str(path_tok.value))
                continue
            module.blocks.append(self._parse_block())
        return module

    def _parse_block(self) -> Block:
        kind_tok = self._expect(TokenType.IDENT)
        name: Optional[str] = None
        if self._peek().type == TokenType.STRING:
            name = str(self._advance().value)
        self._expect(TokenType.LBRACE)
        attrs = {}
        while self._peek().type != TokenType.RBRACE:
            key_tok = self._expect(TokenType.IDENT)
            # nested block shorthand:  key "name" { ... }  OR key { ... }
            if self._peek().type == TokenType.STRING or self._peek().type == TokenType.LBRACE:
                self.pos -= 0
                nested = self._parse_nested_as_block(key_tok.value)
                attrs[key_tok.value] = nested
            else:
                self._expect(TokenType.COLON)
                attrs[key_tok.value] = self._parse_value()
            self._match(TokenType.COMMA)
        self._expect(TokenType.RBRACE)
        return Block(kind=str(kind_tok.value), name=name, attrs=attrs, line=kind_tok.line)

    def _parse_nested_as_block(self, kind: str) -> Block:
        name = None
        if self._peek().type == TokenType.STRING:
            name = str(self._advance().value)
        self._expect(TokenType.LBRACE)
        attrs = {}
        while self._peek().type != TokenType.RBRACE:
            key_tok = self._expect(TokenType.IDENT)
            if self._peek().type == TokenType.STRING or self._peek().type == TokenType.LBRACE:
                attrs[key_tok.value] = self._parse_nested_as_block(key_tok.value)
            else:
                self._expect(TokenType.COLON)
                attrs[key_tok.value] = self._parse_value()
            self._match(TokenType.COMMA)
        self._expect(TokenType.RBRACE)
        return Block(kind=kind, name=name, attrs=attrs)

    def _parse_value(self) -> Value:
        tok = self._peek()
        if tok.type == TokenType.STRING:
            return str(self._advance().value)
        if tok.type == TokenType.NUMBER:
            return self._advance().value  # type: ignore[return-value]
        if tok.type == TokenType.BOOL:
            return bool(self._advance().value)
        if tok.type == TokenType.LBRACKET:
            return self._parse_list()
        if tok.type == TokenType.IDENT:
            # bareword used as an enum-like scalar, e.g.  level: high
            return str(self._advance().value)
        raise ParseError(f"unexpected token in value position: {tok.type.name}", tok)

    def _parse_list(self) -> List[Value]:
        self._expect(TokenType.LBRACKET)
        items: List[Value] = []
        while self._peek().type != TokenType.RBRACKET:
            items.append(self._parse_value())
            self._match(TokenType.COMMA)
        self._expect(TokenType.RBRACKET)
        return items


def parse_source(source: str, source_name: str = "<memory>") -> Module:
    tokens = tokenize(source)
    return Parser(tokens, source_name=source_name).parse_module()


def parse_file(path: str) -> Module:
    with open(path, "r", encoding="utf-8") as fh:
        source = fh.read()
    return parse_source(source, source_name=path)
