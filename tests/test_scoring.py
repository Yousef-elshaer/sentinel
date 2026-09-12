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


def test_limited_coverage_warns_without_changing_low_verdict():
    results = [ProviderResult(provider="working", status=ProviderStatus.SUCCESS, malicious=False),
               ProviderResult(provider="limited", status=ProviderStatus.RATE_LIMITED)]
    score, verdict, reasons = calculate_risk(results)
    assert (score, verdict) == (0, "LOW")
    assert any("score does not confirm" in reason for reason in reasons)
