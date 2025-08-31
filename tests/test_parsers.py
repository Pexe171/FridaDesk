from core.collectors import LogcatCollector, ProcessMetricsCollector


def test_logcat_parse_line():
    collector = LogcatCollector()
    line = "06-24 12:34:56.789 I/Tag: Olá"
    event = collector._parse_line(line)
    assert event is not None
    assert event.level == "I"
    assert event.tag == "Tag"
    assert event.message == "Olá"


def test_top_regex():
    sample = "123 user 10% 0 0 0 2048"
    match = ProcessMetricsCollector.LINE_RE.search(sample)
    assert match is not None
    assert match.group("pid") == "123"
    assert match.group("cpu") == "10"
    assert match.group("rss") == "2048"
