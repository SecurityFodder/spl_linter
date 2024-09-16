import re

# Define regular expressions and patterns for various best practices
BEST_PRACTICES = {
    "no_leading_wildcard": {
        "pattern": re.compile(r"[^\\]\*\w+"),
        "description": "Avoid using wildcards (*) at the beginning of search terms.",
    },
    "explicit_index": {
        "pattern": re.compile(r"\|?\s*search\s+(?!index=)\w+="),
        "description": "Specify the index explicitly in your search to improve performance.",
    },
    "early_time_range": {
        "pattern": re.compile(
            r"^(?!.*time\=).+"
        ),  # Checks if time range is not specified early
        "description": "Specify the time range early in your search to limit data processing.",
    },
    "limit_field_selection": {
        "pattern": re.compile(r"\bselect\s+\*", re.IGNORECASE),
        "description": "Avoid using '*' to select all fields; specify only the necessary fields.",
    },
    "optimize_join_usage": {
        "pattern": re.compile(r"\bjoin\b\s+\[.*\]", re.IGNORECASE),
        "description": "Evaluate if 'join' is necessary; consider using 'lookup' or other commands for better performance.",
    },
    "prefer_tstats": {
        "pattern": re.compile(r"\bstats\b", re.IGNORECASE),
        "description": "Consider using 'tstats' instead of 'stats' for faster statistical operations when applicable.",
    },
    "avoid_unnecessary_commands": {
        "pattern": re.compile(r"\| where 1=1|\| search .*", re.IGNORECASE),
        "description": "Remove unnecessary commands that do not affect the search results.",
    },
    "use_lookups_over_subsearches": {
        "pattern": re.compile(r"\[.*?\]", re.IGNORECASE),
        "description": "Replace subsearches with lookup tables where possible to enhance performance.",
    },
    "efficient_regex_usage": {
        "pattern": re.compile(r"regex\s+\w+\s*=\s*/.*/"),
        "description": "Ensure regular expressions are efficient and not overly complex to avoid performance issues.",
    },
    "leverage_macros_saved_searches": {
        "pattern": re.compile(r"`[a-zA-Z0-9_]+`"),
        "description": "Use macros or saved searches to reuse common search patterns and improve maintainability.",
    },
}


def check_no_leading_wildcard(search_query):
    """
    Check for leading wildcards in search terms.
    """
    violations = []
    pattern = BEST_PRACTICES["no_leading_wildcard"]["pattern"]
    matches = pattern.findall(search_query)
    for match in matches:
        if match.startswith("*"):
            violations.append(BEST_PRACTICES["no_leading_wildcard"]["description"])
    return violations


def check_explicit_index(search_query):
    """
    Ensure that the index is specified explicitly in the search.
    """
    violations = []
    pattern = BEST_PRACTICES["explicit_index"]["pattern"]
    if not re.search(r"index=", search_query, re.IGNORECASE):
        violations.append(BEST_PRACTICES["explicit_index"]["description"])
    return violations


def check_early_time_range(search_query):
    """
    Ensure that the time range is specified early in the search.
    """
    violations = []
    # Typically, time range is specified using earliest= and latest= in the search
    # This check ensures that time range modifiers are present
    if not re.search(r"earliest\s*=\s*|latest\s*=\s*", search_query, re.IGNORECASE):
        violations.append(BEST_PRACTICES["early_time_range"]["description"])
    return violations


def check_limit_field_selection(search_query):
    """
    Ensure that field selection is limited to necessary fields.
    """
    violations = []
    pattern = BEST_PRACTICES["limit_field_selection"]["pattern"]
    if re.search(pattern, search_query):
        violations.append(BEST_PRACTICES["limit_field_selection"]["description"])
    return violations


def check_optimize_join_usage(search_query):
    """
    Check for the use of 'join' and suggest alternatives.
    """
    violations = []
    pattern = BEST_PRACTICES["optimize_join_usage"]["pattern"]
    if re.search(pattern, search_query):
        violations.append(BEST_PRACTICES["optimize_join_usage"]["description"])
    return violations


def check_prefer_tstats(search_query):
    """
    Suggest using 'tstats' over 'stats' where applicable.
    """
    violations = []
    # This is a heuristic; ideally, you would parse the search to determine if tstats is applicable
    pattern = BEST_PRACTICES["prefer_tstats"]["pattern"]
    if re.search(pattern, search_query):
        violations.append(BEST_PRACTICES["prefer_tstats"]["description"])
    return violations


def check_avoid_unnecessary_commands(search_query):
    """
    Identify and flag unnecessary commands in the search pipeline.
    """
    violations = []
    pattern = BEST_PRACTICES["avoid_unnecessary_commands"]["pattern"]
    matches = pattern.findall(search_query)
    for match in matches:
        violations.append(BEST_PRACTICES["avoid_unnecessary_commands"]["description"])
    return violations


def check_use_lookups_over_subsearches(search_query):
    """
    Encourage the use of lookups instead of subsearches.
    """
    violations = []
    pattern = BEST_PRACTICES["use_lookups_over_subsearches"]["pattern"]
    matches = pattern.findall(search_query)
    for match in matches:
        violations.append(BEST_PRACTICES["use_lookups_over_subsearches"]["description"])
    return violations


def check_efficient_regex_usage(search_query):
    """
    Ensure that regular expressions used in the search are efficient.
    """
    violations = []
    pattern = BEST_PRACTICES["efficient_regex_usage"]["pattern"]
    matches = pattern.findall(search_query)
    for match in matches:
        # Simple check to warn about regex usage; more complex analysis can be implemented
        if len(match) > 100:  # Arbitrary length to flag potentially complex regex
            violations.append(BEST_PRACTICES["efficient_regex_usage"]["description"])
    return violations


def check_leverage_macros_saved_searches(search_query):
    """
    Suggest using macros or saved searches for common patterns.
    """
    violations = []
    pattern = BEST_PRACTICES["leverage_macros_saved_searches"]["pattern"]
    matches = pattern.findall(search_query)
    for match in matches:
        # If macros are used, it's a good practice; if not, suggest their use
        # This simplistic check assumes that presence of macros is good
        # You might want to invert this logic based on your organization's practices
        if not matches:
            violations.append(
                BEST_PRACTICES["leverage_macros_saved_searches"]["description"]
            )
    return violations


def check_best_practices(search_name, search_query):
    """
    Check if the search adheres to Splunk best practices.
    Returns a list of violated practices.
    """
    violations = []

    # Check for leading wildcards
    violations += check_no_leading_wildcard(search_query)

    # Check for explicit index specification
    violations += check_explicit_index(search_query)

    # Check for early time range specification
    violations += check_early_time_range(search_query)

    # Check for limiting field selection
    violations += check_limit_field_selection(search_query)

    # Check for optimizing join usage
    violations += check_optimize_join_usage(search_query)

    # Check if 'tstats' can be used instead of 'stats'
    violations += check_prefer_tstats(search_query)

    # Check for unnecessary commands
    violations += check_avoid_unnecessary_commands(search_query)

    # Check for use of lookups over subsearches
    violations += check_use_lookups_over_subsearches(search_query)

    # Check for efficient regex usage
    violations += check_efficient_regex_usage(search_query)

    # Check for leveraging macros or saved searches
    violations += check_leverage_macros_saved_searches(search_query)

    return violations
