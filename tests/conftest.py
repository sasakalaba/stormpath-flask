from .helpers import bootstrap_client


def pytest_keyboard_interrupt(excinfo):
    collection_resources = ['applications', 'directories']
    test_prefix = 'flask-stormpath-tests'
    client = bootstrap_client()

    for collection in collection_resources:
        for resource in list(getattr(client, collection).search(test_prefix)):
            resource.delete()
