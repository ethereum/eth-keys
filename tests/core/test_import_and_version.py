def test_import_and_version():
    import eth_keys

    assert isinstance(eth_keys.__version__, str)
