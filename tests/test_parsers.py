from core.collectors import LogcatCollector


def test_logcat_parse_line():
    collector = LogcatCollector()
    line = "06-24 12:34:56.789 I/Tag: Olá"
    event = collector._parse_line(line)
    assert event is not None
    assert event.level == "I"
    assert event.tag == "Tag"
    assert event.message == "Olá"
