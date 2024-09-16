import argparse
from saved_search_loader import load_saved_searches
from best_practices import check_best_practices
from cim_validation import check_cim_compliance
from syntax_checker import check_syntax
from formatter import format_search


def main():
    parser = argparse.ArgumentParser(
        description="Splunk Saved Searches Static Analysis Suite"
    )
    parser.add_argument("--host", required=True, help="Splunk host")
    parser.add_argument("--port", type=int, default=8089, help="Splunk management port")
    parser.add_argument("--username", required=True, help="Splunk username")
    parser.add_argument("--password", required=True, help="Splunk password")
    parser.add_argument("--app", default="search", help="Splunk app context")

    args = parser.parse_args()

    print("Loading saved searches...")
    searches = load_saved_searches(
        args.host, args.port, args.username, args.password, app=args.app
    )

    report = {}

    for name, query in searches.items():
        print(f"Analyzing search: {name}")
        report[name] = {
            "violations": check_best_practices(name, query),
            "cim_issues": check_cim_compliance(query),
            "syntax": check_syntax(query),
            "formatted_search": format_search(query),
        }

    # Output the report
    for name, details in report.items():
        print(f"\n--- Report for '{name}' ---")
        if details["violations"]:
            print("Best Practices Violations:")
            for v in details["violations"]:
                print(f"  - {v}")
        else:
            print("No Best Practices Violations.")

        if details["cim_issues"]:
            print("CIM Compliance Issues:")
            for c in details["cim_issues"]:
                print(f"  - {c} not normalized to CIM.")
        else:
            print("All fields are CIM compliant.")

        if details["syntax"] is True:
            print("Syntax: Correct")
        else:
            print(f"Syntax: {details['syntax']}")

        print("\nFormatted Search:")
        print(details["formatted_search"])


if __name__ == "__main__":
    main()
