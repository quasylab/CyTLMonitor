"""
cytlmonitor.language.lexer
==========================
Splitting a specification into sections, entries and tokens.

A specification is a sequence of *sections*. Each section starts with a line
holding its name alone, at the very beginning of the line (``constants``,
``events``, ``links``, ``values``, ``counters``, ``measures``,
``properties`` or ``show``), optionally followed by ``:``. The lines of a
section are indented: the first one fixes the indentation of its *entries*,
every line indented as much starts a new entry, and every line indented more
continues the entry above it. ``#`` starts a comment, up to the end of the
line, and blank lines are ignored.

:func:`entries` returns, for every entry, its section and its tokens. A
:class:`Token` records where it was found, so that errors can point at it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional, Tuple

SECTIONS = ('constants', 'events', 'links', 'values', 'counters', 'measures',
            'properties', 'show')

NAME, NUMBER, STRING, SYMBOL, END = 'name', 'number', 'string', 'symbol', 'end'

_TOKEN = re.compile(r'''
    (?P<space>[ \t]+)
  | (?P<comment>\#.*)
  | (?P<number>(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?)
  | (?P<name>[A-Za-z_][A-Za-z0-9_]*)
  | (?P<string>"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')
  | (?P<symbol><=|>=|==|!=|[<>+\-*/(),.=:\[\]])
''', re.VERBOSE)

_ESCAPES = {'n': '\n', 't': '\t', '\\': '\\', '"': '"', "'": "'"}


class SpecificationError(Exception):
    """An error in a specification, at a given line and column (both
    counted from 1) when it is known."""

    def __init__(self, message: str, line: Optional[int] = None,
                 column: Optional[int] = None, text: Optional[str] = None):
        self.message = message
        self.line = line
        self.column = column
        self.text = text
        super().__init__(self._render())

    def _render(self) -> str:
        if self.line is None:
            return self.message
        where = f'line {self.line}' + (f', column {self.column}' if self.column else '')
        rendered = f'{where}: {self.message}'
        if self.text is not None:
            rendered += f'\n    {self.text}'
            if self.column:
                rendered += '\n    ' + ' ' * (self.column - 1) + '^'
        return rendered


@dataclass(frozen=True)
class Token:
    """A token: its kind, its value (the text of a name or a symbol, the
    number, the content of a string), and where it is in the source."""

    kind: str
    value: object
    line: int
    column: int
    start: int
    end: int

    def is_word(self, *words: str) -> bool:
        """True if the token is one of the names ``words``."""
        return self.kind == NAME and self.value in words

    def is_symbol(self, *symbols: str) -> bool:
        """True if the token is one of the symbols ``symbols``."""
        return self.kind == SYMBOL and self.value in symbols

    def describe(self) -> str:
        """The token as written in an error message."""
        if self.kind == END:
            return 'the end of the entry'
        if self.kind == STRING:
            return f'"{self.value}"'
        return f"'{self.value}'"


@dataclass
class Entry:
    """An entry of a section: its tokens, ending with an END token."""

    section: str
    tokens: List[Token]


def _string(text: str) -> str:
    body = text[1:-1]
    return re.sub(r'\\(.)', lambda m: _ESCAPES.get(m.group(1), m.group(1)), body)


def tokenize_line(source: str, line: str, number: int, offset: int) -> List[Token]:
    """The tokens of ``line``, the line ``number`` of ``source`` starting at
    ``offset``."""
    tokens = []
    position = 0
    while position < len(line):
        match = _TOKEN.match(line, position)
        if match is None:
            raise SpecificationError(f"unexpected character {line[position]!r}",
                                     number, position + 1, line)
        kind = match.lastgroup
        text = match.group()
        if kind == 'number':
            tokens.append(Token(NUMBER, float(text), number, position + 1,
                                offset + position, offset + match.end()))
        elif kind == 'name':
            tokens.append(Token(NAME, text, number, position + 1,
                                offset + position, offset + match.end()))
        elif kind == 'string':
            tokens.append(Token(STRING, _string(text), number, position + 1,
                                offset + position, offset + match.end()))
        elif kind == 'symbol':
            tokens.append(Token(SYMBOL, text, number, position + 1,
                                offset + position, offset + match.end()))
        position = match.end()
    return tokens


def entries(source: str) -> List[Entry]:
    """Split ``source`` into the entries of its sections."""
    result: List[Entry] = []
    section: Optional[str] = None
    indent: Optional[int] = None
    offset = 0
    lines = source.split('\n')
    for number, raw in enumerate(lines, start=1):
        line = raw.rstrip('\r')
        start = offset
        offset += len(raw) + 1
        tokens = tokenize_line(source, line, number, start)
        if not tokens:
            continue
        column = len(line[:tokens[0].column - 1].expandtabs(4))
        if column == 0:
            header = tokens[0]
            rest = tokens[1:]
            if rest and rest[0].is_symbol(':'):
                rest = rest[1:]
            if header.kind != NAME or header.value not in SECTIONS or rest:
                raise SpecificationError(
                    'a line that is not indented must name a section: '
                    + ', '.join(SECTIONS) + '; indent the lines of a section',
                    number, 1, line)
            section, indent = header.value, None
            continue
        if section is None:
            raise SpecificationError('an indented line before the first section', number,
                                     tokens[0].column, line)
        if indent is None or column == indent:
            indent = column
            result.append(Entry(section, tokens))
        elif column > indent:
            result[-1].tokens.extend(tokens)
        else:
            raise SpecificationError(
                f'this line is indented less than the first entry of the section '
                f'({indent} spaces)', number, tokens[0].column, line)
    for entry in result:
        last = entry.tokens[-1]
        entry.tokens.append(Token(END, None, last.line, last.column + (last.end - last.start),
                                  last.end, last.end))
    return result


def source_line(source: str, number: int) -> str:
    """The line ``number`` of ``source``."""
    lines = source.split('\n')
    return lines[number - 1].rstrip('\r') if 0 < number <= len(lines) else ''


def span(source: str, first: Token, last: Token) -> str:
    """The text of ``source`` from ``first`` to ``last``, on a single line."""
    return ' '.join(source[first.start:last.end].split())


__all__: Tuple[str, ...] = ('SpecificationError', 'Token', 'Entry', 'entries', 'SECTIONS')
