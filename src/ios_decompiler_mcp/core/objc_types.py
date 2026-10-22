from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from ios_decompiler_mcp.core.errors import Code, MCPError

_SCALARS = {"v": "void", "@": "id", "#": "Class", ":": "SEL", "c": "signed char", "C": "unsigned char", "s": "short", "S": "unsigned short", "i": "int", "I": "unsigned int", "l": "long", "L": "unsigned long", "q": "long long", "Q": "unsigned long long", "f": "float", "d": "double", "B": "BOOL", "*": "char *"}
_STRUCTS = {"CGRect", "CGPoint", "CGSize", "NSRange", "_NSRange", "UIEdgeInsets", "CGAffineTransform"}


@dataclass(frozen=True)
class CType:
    encoding: str
    spelling: str
    certain: bool = True


def decode_encoding(encoding: str) -> list[CType]:
    """Parse complete tokens, including nested aggregates; never guess an ABI."""
    types: list[CType] = []
    position = 0
    while position < len(encoding):
        if encoding[position].isdigit() or encoding[position] in "+- ":
            position += 1
            continue
        start = position
        while position < len(encoding) and encoding[position] in "rnNoORV":
            position += 1
        if position == len(encoding):
            raise MCPError(Code.INVALID_INPUT, "Incomplete Objective-C type encoding")
        char = encoding[position]
        position += 1
        if char == "@" and position < len(encoding) and encoding[position] == "?":
            position += 1
            spelling, certain = "id /* block signature unknown */", False
        elif char == "@" and position < len(encoding) and encoding[position] == '"':
            end = encoding.find('"', position + 1)
            if end == -1:
                raise MCPError(Code.INVALID_INPUT, "Unterminated Objective-C object encoding")
            name = encoding[position + 1:end]
            certain = bool(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name))
            spelling = name + " *" if certain else "id /* protocol/object type uncertain */"
            position = end + 1
        elif char in "{[(":
            closing = {"{": "}", "[": "]", "(": ")"}[char]
            stack = [closing]
            while stack and position < len(encoding):
                current = encoding[position]
                position += 1
                if current in "{[(":
                    stack.append({"{": "}", "[": "]", "(": ")"}[current])
                elif current == stack[-1]:
                    stack.pop()
            if stack:
                raise MCPError(Code.INVALID_INPUT, "Unterminated aggregate type encoding")
            token = encoding[start:position]
            name = token[token.find("{") + 1:].split("=", 1)[0].rstrip("}")
            certain = char == "{" and name in _STRUCTS
            spelling = "NSRange" if name == "_NSRange" else name if certain else "id /* unsupported aggregate ABI */"
        elif char == "^":
            # Consume a single nested token; unknown pointers are useful in headers but
            # not safe enough to auto-generate an arbitrary hook signature.
            nested = decode_encoding(encoding[position:])
            if not nested:
                raise MCPError(Code.INVALID_INPUT, "Incomplete pointer encoding")
            position += len(nested[0].encoding)
            spelling, certain = nested[0].spelling + " *", nested[0].certain
        elif char == "b":
            while position < len(encoding) and encoding[position].isdigit():
                position += 1
            spelling, certain = "unsigned int /* bitfield width requires manual declaration */", False
        else:
            spelling, certain = _SCALARS.get(char, "id /* unknown ABI */"), char in _SCALARS
        types.append(CType(encoding[start:position], spelling, certain))
    return types


def signature(selector: str, encoding: str, class_method: bool = False) -> tuple[str, bool]:
    types = decode_encoding(encoding)
    count = selector.count(":")
    if len(types) != count + 3 or types[1].encoding.lstrip("rnNoORV") not in {"@", "#"} or types[2].encoding != ":":
        raise MCPError(Code.INVALID_INPUT, "Method encoding does not match selector argument count", selector=selector, encoding=encoding)
    prefix = "+" if class_method else "-"
    declaration = f"{prefix} ({types[0].spelling})"
    if count:
        parts = selector.split(":")[:-1]
        declaration += " ".join(f"{part}:({kind.spelling})arg{index}" for index, (part, kind) in enumerate(zip(parts, types[3:], strict=True)))
    else:
        declaration += selector
    return declaration, all(item.certain for item in types)


def header(data: dict[str, Any]) -> str:
    name, parent = data["class_name"], data.get("superclass") or "NSObject"
    lines = ["// Generated from observed Objective-C metadata; '?' comments require manual review.", "// Pure Swift metadata is not reconstructed. Names do not establish semantic behavior.", "#import <UIKit/UIKit.h>", f"@interface {name} : {parent}"]
    for method in data.get("methods", {}).get("methods", []):
        try:
            declaration, certain = signature(method["selector"], method["type_encoding"], method["class_method"])
            lines.append(declaration + ";" + ("" if certain else " // ? inferred/unsupported type; do not compile without review"))
        except MCPError:
            lines.append(f"// ? Unsupported encoding for selector {method['selector']!r}: {method['type_encoding']!r}")
    for item in data.get("properties", {}).get("properties", []):
        lines.append(f"// Observed property {item['name']}: {item['attributes']}")
    lines.append("@end")
    return "\n".join(lines) + "\n"
