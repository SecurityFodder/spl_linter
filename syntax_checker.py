import os
import sys
import argparse
import getpass
import splunklib.client as client
import splunklib.results as results
from splunklib.binding import HTTPError
import logging
from typing import Dict, Any, List

# Configure logging
logging.basicConfig(
    filename='syntax_checker.log',
    filemode='a',
    format='%(asctime)s - %(levelname)s - %(message)s',
    level=logging.INFO
)

def get_credentials(args) -> Dict[str, Any]:
    """
    Retrieve Splunk credentials from environment variables or prompt the user.
    """
    splunk_host = os.getenv('SPLUNK_HOST') or args.host
    splunk_port = os.getenv('SPLUNK_PORT') or args.port
    splunk_username = os.getenv('SPLUNK_USERNAME') or args.username
    splunk_password = os.getenv('SPLUNK_PASSWORD') or args.password

    # Prompt for any missing credentials
    if not splunk_host:
        splunk_host = input("Enter Splunk host: ")
    if not splunk_port:
        splunk_port = input("Enter Splunk management port (default 8089): ") or '8089'
    if not splunk_username:
        splunk_username = input("Enter Splunk username: ")
    if not splunk_password:
        splunk_password = getpass.getpass("Enter Splunk password: ")

    return {
        "host": splunk_host,
        "port": int(splunk_port),
        "username": splunk_username,
        "password": splunk_password
    }

def connect_splunk(credentials: Dict[str, Any], app: str = 'search') -> client.Service:
    """
    Establish a connection to the Splunk service.
    """
    try:
        service = client.connect(
            host=credentials['host'],
            port=credentials['port'],
            username=credentials['username'],
            password=credentials['password'],
            app=app,
            scheme="https"  # Assuming HTTPS; change to "http" if necessary
        )
        logging.info(f"Connected to Splunk at {credentials['host']}:{credentials['port']} as {credentials['username']}")
        return service
    except HTTPError as e:
        logging.error(f"HTTPError during Splunk connection: {e}")
        sys.exit(f"Failed to connect to Splunk: {e}")
    except Exception as e:
        logging.error(f"Exception during Splunk connection: {e}")
        sys.exit(f"Failed to connect to Splunk: {e}")

def load_saved_searches(service: client.Service, app: str = 'search') -> Dict[str, str]:
    """
    Retrieve saved searches from the specified Splunk app.
    """
    try:
        saved_searches = service.saved_searches.list()
        searches = {}
        for search in saved_searches:
            if search.name.startswith('_'):  # Skip internal searches
                continue
            searches[search.name] = search.search
        logging.info(f"Loaded {len(searches)} saved searches from app '{app}'")
        return searches
    except Exception as e:
        logging.error(f"Error loading saved searches: {e}")
        sys.exit(f"Failed to load saved searches: {e}")

def check_syntax(service: client.Service, search_query: str) -> Dict[str, Any]:
    """
    Check the syntax of a Splunk search query using parse_only=1.
    Returns a dictionary with the status and any error messages.
    """
    try:
        kwargs = {
            "exec_mode": "blocking",
            "parse_only": "1",
            "earliest_time": "0",
            "latest_time": "now"
        }
        job = service.jobs.create(search_query, **kwargs)
        # If the job completes without errors, syntax is correct
        if job["dispatchState"] == "DONE":
            logging.info("Syntax is correct.")
            return {"status": "Correct", "error": None}
        else:
            # Retrieve results to find any errors
            reader = results.ResultsReader(job.results())
            for result in reader:
                if isinstance(result, dict) and 'ERROR' in result:
                    error_message = result.get('ERROR')
                    logging.warning(f"Syntax error: {error_message}")
                    return {"status": "Error", "error": error_message}
            logging.info("Syntax is correct.")
            return {"status": "Correct", "error": None}
    except HTTPError as e:
        error_msg = f"HTTPError during syntax check: {e}"
        logging.error(error_msg)
        return {"status": "Error", "error": error_msg}
    except Exception as e:
        error_msg = f"Exception during syntax check: {e}"
        logging.error(error_msg)
        return {"status": "Error", "error": error_msg}

def main():
    parser = argparse.ArgumentParser(description="Splunk Saved Searches Syntax Checker")
    parser.add_argument('--host', help='Splunk host address')
    parser.add_argument('--port', type=int, help='Splunk management port (default: 8089)')
    parser.add_argument('--username', help='Splunk username')
    parser.add_argument('--password', help='Splunk password')
    parser.add_argument('--app', default='search', help='Splunk app context (default: search)')
    parser.add_argument('--output', default='syntax_report.txt', help='Output report file (default: syntax_report.txt)')
    args = parser.parse_args()

    # Retrieve credentials
    credentials = get_credentials(args)

    # Connect to Splunk
    service = connect_splunk(credentials, app=args.app)

    # Load saved searches
    saved_searches = load_saved_searches(service, app=args.app)

    # Initialize report data structure
    report = {}

    # Iterate over saved searches and check syntax
    for name, query in saved_searches.items():
        logging.info(f"Checking syntax for saved search: {name}")
        syntax_result = check_syntax(service, query)
        report[name] = syntax_result

    # Write report to file
    try:
        with open(args.output, 'w') as f:
            f.write("Splunk Saved Searches Syntax Report\n")
            f.write("===================================\n\n")
            for name, result in report.items():
                f.write(f"Search Name: {name}\n")
                f.write(f"Status: {result['status']}\n")
                if result['error']:
                    f.write(f"Error: {result['error']}\n")
                f.write("\n")
        logging.info(f"Syntax report written to {args.output}")
        print(f"Syntax report successfully written to {args.output}")
    except Exception as e:
        logging.error(f"Failed to write report to file: {e}")
        sys.exit(f"Failed to write report to file: {e}")

if __name__ == "__main__":
    main()
