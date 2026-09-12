import pytest

from app.schemas import ProviderResult, ProviderStatus
from app.scoring import calculate_risk, verdict_for


@pytest.mark.parametrize(("score","verdict"),[(0,"LOW"),(24,"LOW"),(25,"MEDIUM"),(49,"MEDIUM"),(50,"HIGH"),(74,"HIGH"),(75,"CRITICAL"),(100,"CRITICAL")])
def test_boundaries(score,verdict): assert verdict_for(score)==verdict

def test_known_exploited_is_explainable():
    result=ProviderResult(provider="CISA KEV",status=ProviderStatus.SUCCESS,malicious=True,confidence=100,malicious_detections=1,categories=["known_exploited"])
    score,verdict,reasons=calculate_risk([result])
    assert score==63 and verdict=="HIGH" and any("CISA" in reason for reason in reasons)

def test_no_signal_is_low():
    score,verdict,reasons=calculate_risk([ProviderResult(provider="x",status=ProviderStatus.SUCCESS,malicious=False)])
    assert (score,verdict)==(0,"LOW") and reasons[0].startswith("+0")


@pytest.mark.parametrize("status", [s for s in ProviderStatus if s != ProviderStatus.SUCCESS])
def test_unavailable_checks_are_unknown(status):
    score, verdict, reasons = calculate_risk([ProviderResult(provider="x", status=status)])
    assert score is None and verdict == "UNKNOWN"
    assert "Insufficient data" in reasons[0]


def test_no_providers_is_unknown():
    assert calculate_risk([])[:2] == (None, "UNKNOWN")


def test_partial_coverage_preserves_evidence():
    results = [ProviderResult(provider="x", status=ProviderStatus.SUCCESS, malicious=True,
                              confidence=100, malicious_detections=1, categories=["known_exploited"]),
               ProviderResult(provider="y", status=ProviderStatus.TIMEOUT)]
    score, verdict, reasons = calculate_risk(results)
    assert (score, verdict) == (63, "HIGH")
    assert any("Partial coverage" in reason for reason in reasons)
