import pytest

# Change COLLECT_TYPE_INFO to True here, and run the tests with python2.7 to get a type
# info dump that can later be fed to pyannotate to generate type annotation comments.
COLLECT_TYPE_INFO = False

if COLLECT_TYPE_INFO:
    from pyannotate_runtime import (
        collect_types,
    )

    @pytest.fixture(autouse=True)
    def collect_types_fixture():
        collect_types.resume()
        yield
        collect_types.pause()

    def pytest_sessionstart(session):
        collect_types.init_types_collection()

    def pytest_sessionfinish(session, exitstatus):
        collect_types.dump_stats("type_info.json")
