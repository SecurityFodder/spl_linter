import re
from collections import defaultdict

# Define CIM-compliant fields for various data sources
CIM_FIELD_MAPPINGS = {
    "common": {
        "src_ip": "source",
        "dst_ip": "destination",
        "user": "user",
        "host": "host",
        "sourcetype": "sourcetype",
        "index": "index",
        "source": "source",
        "event_id": "event_id",
        "action": "action",
        "status": "status",
        "uri": "uri",
        "method": "method",
        # Add more common CIM fields as needed
    },
    "crowdstrike": {
        "device_id": "device",
        "process_name": "process",
        "user_id": "user",
        "alert_id": "alert_id",
        # Add more CrowdStrike-specific CIM fields
    },
    "bluecoat": {
        "url": "uri",
        "response_code": "status",
        "action_taken": "action",
        "bytes_transferred": "bytes",
        # Add more Bluecoat-specific CIM fields
    },
    "checkpoint": {
        "policy_name": "policy",
        "rule_number": "rule_number",
        "source_zone": "source_zone",
        "destination_zone": "destination_zone",
        # Add more Checkpoint-specific CIM fields
    },
    "windows": {
        "win_logon_id": "logon_id",
        "win_event_code": "event_code",
        "win_account_name": "account",
        "win_process_id": "process_id",
        # Add more Windows-specific CIM fields
    },
    "aws": {
        "aws_account_id": "account_id",
        "aws_region": "region",
        "aws_service": "service",
        "aws_event_type": "event_type",
        # Add more AWS-specific CIM fields
    },
    "gcp": {
        "gcp_project_id": "project_id",
        "gcp_region": "region",
        "gcp_service": "service",
        "gcp_event_type": "event_type",
        # Add more GCP-specific CIM fields
    },
}

# Flatten all CIM fields for easy lookup
ALL_CIM_FIELDS = set()
for source_fields in CIM_FIELD_MAPPINGS.values():
    ALL_CIM_FIELDS.update(source_fields.values())

# Patterns to identify commands and their arguments
COMMAND_PATTERNS = {
    "rename": re.compile(r'rename\s+(.*?)\s+as\s+(.*?)($|\s|$)', re.IGNORECASE),
    "eval": re.compile(r'eval\s+(.*?)\s*=', re.IGNORECASE),
    "stats": re.compile(r'stats\s+(.*?)\s+by\s+(.*)', re.IGNORECASE),
    "lookup": re.compile(r'lookup\s+(.*?)\s+(.*?)\s+OUTPUT(?:NEW)?\s+(.*)', re.IGNORECASE),
}

def extract_fields_from_rename(command):
    """
    Extract fields being renamed.
    """
    fields = []
    matches = COMMAND_PATTERNS["rename"].findall(command)
    for match in matches:
        old_field, new_field, _ = match
        fields.append((old_field.strip(), new_field.strip()))
    return fields

def extract_fields_from_eval(command):
    """
    Extract fields being created or modified in eval.
    """
    fields = []
    matches = COMMAND_PATTERNS["eval"].findall(command)
    for match in matches:
        field = match.strip()
        fields.append(field)
    return fields

def extract_fields_from_stats(command):
    """
    Extract fields used in stats commands.
    """
    fields = []
    matches = COMMAND_PATTERNS["stats"].findall(command)
    for match in matches:
        agg_fields, by_fields = match
        # Extract aggregation fields
        agg_parts = agg_fields.split(',')
        for part in agg_parts:
            # Handle possible aliases in aggregation
            agg_match = re.match(r'\s*\w+\((.*?)\)\s*as\s*(\w+)', part.strip(), re.IGNORECASE)
            if agg_match:
                _, alias = agg_match.groups()
                fields.append(alias.strip())
            else:
                # If no alias, extract the field inside the aggregation
                agg_inner = re.findall(r'\w+\((.*?)\)', part)
                if agg_inner:
                    fields.append(agg_inner[0].strip())
        # Extract by fields
        by_parts = by_fields.split(',')
        for part in by_parts:
            field = part.strip()
            fields.append(field)
    return fields

def extract_fields_from_lookup(command):
    """
    Extract fields used and created in lookup commands.
    """
    fields = []
    matches = COMMAND_PATTERNS["lookup"].findall(command)
    for match in matches:
        lookup_table, input_fields, output_fields = match
        input_fields = [f.strip() for f in input_fields.split(',')]
        output_fields = [f.strip() for f in output_fields.split(',')]
        fields.extend(input_fields + output_fields)
    return fields

def parse_search_query(search_query):
    """
    Parse the search query and extract all fields used or created via specific commands.
    """
    # Split the search query into individual commands based on '|'
    commands = [cmd.strip() for cmd in search_query.split('|') if cmd.strip()]
    
    # Initialize a dictionary to hold fields categorized by their usage
    fields_usage = defaultdict(set)
    
    for cmd in commands:
        # Identify the command type
        cmd_type_match = re.match(r'(\w+)', cmd)
        if not cmd_type_match:
            continue
        cmd_type = cmd_type_match.group(1).lower()
        
        if cmd_type == 'rename':
            renamed_fields = extract_fields_from_rename(cmd)
            for old, new in renamed_fields:
                fields_usage['renamed'].add(new)
        elif cmd_type == 'eval':
            eval_fields = extract_fields_from_eval(cmd)
            for field in eval_fields:
                fields_usage['created'].add(field)
        elif cmd_type == 'stats':
            stats_fields = extract_fields_from_stats(cmd)
            for field in stats_fields:
                fields_usage['used'].add(field)
        elif cmd_type == 'lookup':
            lookup_fields = extract_fields_from_lookup(cmd)
            for field in lookup_fields:
                fields_usage['used'].add(field)
        elif cmd_type in ['search', 'where', 'table', 'fields', 'fillnull', 'coalesce']:
            # These commands use fields but do not create them
            # Extract fields using regex to find field names
            used_fields = re.findall(r'\b(\w+)=', cmd)
            if not used_fields:
                # Alternative pattern to capture fields without '='
                used_fields = re.findall(r'\b(\w+)\b', cmd)
            for field in used_fields:
                fields_usage['used'].add(field)
        # Add more command types as needed
    
    return fields_usage

def check_cim_compliance(search_name, search_query):
    """
    Check if the search adheres to CIM normalization.
    Returns a list of non-compliant fields with details.
    """
    violations = []
    fields_usage = parse_search_query(search_query)
    
    # Combine all fields used and created
    all_fields = set()
    for usage in fields_usage.values():
        all_fields.update(usage)
    
    # Check each field for CIM compliance
    for field in all_fields:
        if field not in ALL_CIM_FIELDS:
            # Attempt to find if the field can be mapped via source-specific mappings
            # This requires knowing the data source; for simplicity, we check all mappings
            mapped = False
            for source, mappings in CIM_FIELD_MAPPINGS.items():
                if field in mappings:
                    mapped = True
                    break
            if not mapped:
                violations.append({
                    "field": field,
                    "issue": "Field is not CIM-compliant.",
                    "suggestion": "Map the field to a CIM-compliant field or use field aliases to conform to CIM."
                })
    
    return violations

def get_field_aliases():
    """
    Generate a reverse mapping from CIM fields to source-specific fields.
    Useful for suggesting possible aliases.
    """
    aliases = defaultdict(list)
    for source, mappings in CIM_FIELD_MAPPINGS.items():
        for custom_field, cim_field in mappings.items():
            aliases[cim_field].append(custom_field)
    return aliases

def suggest_alias(field):
    """
    Suggest possible CIM-compliant aliases for a non-compliant field.
    """
    aliases = get_field_aliases()
    suggestions = []
    for cim_field, custom_fields in aliases.items():
        if field.lower() in [cf.lower() for cf in custom_fields]:
            suggestions.append(cim_field)
    return suggestions

if __name__ == "__main__":
    # Example usage
    search_name = "Sample Search"
    search_query = """
        index=aws_cloudtrail sourcetype=aws:cloudtrail
        | rename eventName as action, sourceIPAddress as src_ip
        | eval user_fullname = user.first + " " + user.last
        | stats count by src_ip, user_fullname
        | lookup aws_regions region_code as src_region OUTPUTNEW region_name as src_region_name
        | where count > 100
    """
    
    violations = check_cim_compliance(search_name, search_query)
    
    if violations:
        print(f"CIM Compliance Issues for '{search_name}':")
        for v in violations:
            print(f" - Field: {v['field']}")
            print(f"   Issue: {v['issue']}")
            print(f"   Suggestion: {v['suggestion']}\n")
    else:
        print(f"All fields in '{search_name}' are CIM compliant.")
