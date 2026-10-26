"""S2 / B12: analyzer resource/keyword maps must equal the live server risk_scorer maps."""
import risk_scorer  # resolved via pytest.ini pythonpath (. server); seismograph itself never imports server/
from seismograph import analyzer
from seismograph.analyzer import SeismographAnalyzer


def test_resource_map_equals_risk_scorer():
    assert len(risk_scorer.RESOURCE_MAP) == 13
    assert analyzer.TOOL_RESOURCE_MAP == risk_scorer.RESOURCE_MAP


def test_keyword_map_covers_all_tools_and_agrees_with_risk_scorer():
    assert set(analyzer.TOOL_KEYWORD_MAP) == set(risk_scorer.RESOURCE_MAP)
    for tool, kws in risk_scorer.TOOL_KEYWORDS.items():
        assert analyzer.TOOL_KEYWORD_MAP[tool] == kws


def test_seismograph_does_not_import_server():
    import pathlib
    root = pathlib.Path(analyzer.__file__).parent
    for f in root.glob("*.py"):
        if f.name.startswith("test_"):
            continue
        src = f.read_text()
        assert "risk_scorer" not in src.replace("server/risk_scorer.py", "")
        assert "from server" not in src and "import server" not in src


class _Stub:
    def embed(self, t):
        return [0.0] * 4


def test_circumvention_slack_after_email_denied():
    a = SeismographAnalyzer(embedder=_Stub())
    a.register_denial("send_email")
    alert = a.check_circumvention("send_slack_message", "n1", 4.0)
    assert alert and alert["trigger"] == "circumvention_detected"


def test_read_file_is_filesystem_not_data():
    a = SeismographAnalyzer(embedder=_Stub())
    a.register_denial("query_database")
    assert a.check_circumvention("read_file", "n1", 4.0) is None
    a.register_denial("write_file")
    assert a.check_circumvention("read_file", "n1", 4.0) is not None
