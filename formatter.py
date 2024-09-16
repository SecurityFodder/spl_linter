from pyparsing import (
    Word,
    alphas,
    alphanums,
    Group,
    oneOf,
    ZeroOrMore,
    Optional,
    restOfLine,
    Suppress,
    Keyword,
)


def format_search(search_query):
    """
    Format the Splunk search query to be well laid out and easy to read.
    This is a simplistic formatter. For more advanced formatting, consider using a proper parser.
    """
    # Simple indentation based on pipe '|'
    lines = search_query.split("|")
    formatted_lines = [lines[0].strip()]
    for line in lines[1:]:
        formatted_lines.append("  | " + line.strip())
    return "\n".join(formatted_lines)
