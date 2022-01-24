from flaat.issuertools import is_url


class TestURLs:
    def test_url_1(self):
        assert is_url("http://heise.de")

    def test_valid_url_http(self):
        assert is_url("http://heise.de")

    def test_valid_url_https(self):
        assert is_url("http://heise.de")

    def test_valid_url_ftp(self):
        assert is_url("http://heise.de")

    def test_valid_url_https_path(self):
        assert is_url("https://heise.de/thi_s&is=difficult")

    def test_invalid_url(self):
        assert not is_url("htp://heise.de")
