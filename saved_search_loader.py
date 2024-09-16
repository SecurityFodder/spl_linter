import splunklib.client as client
import splunklib.binding as binding

def load_saved_searches(splunk_host, splunk_port, username, password, app='search'):
    """
    Connect to Splunk and retrieve saved searches.
    """
    service = client.connect(
        host=splunk_host,
        port=splunk_port,
        username=username,
        password=password,
        app=app
    )

    saved_searches = service.saved_searches.list()
    searches = {}
    for search in saved_searches:
        searches[search.name] = search.search
    return searches
