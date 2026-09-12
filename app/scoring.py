from app.schemas import ProviderResult, ProviderStatus


def verdict_for(score: int) -> str:
    if score >= 75: return "CRITICAL"
    if score >= 50: return "HIGH"
    if score >= 25: return "MEDIUM"
    return "LOW"


def calculate_risk(results: list[ProviderResult]) -> tuple[int | None, str, list[str]]:
    successful = [r for r in results if r.status == ProviderStatus.SUCCESS]
    if not successful:
        return None, "UNKNOWN", [
            ("Insufficient data: no intelligence provider completed a check successfully. "
            "Missing API keys, rate limits, or provider failures may prevent assessment. "
            "This is not evidence that the indicator is safe.")
        ]
    flagged = [r for r in successful if r.malicious]
    points: list[tuple[int, str]] = []
    if flagged:
        detection_points = min(35, sum(min(r.malicious_detections or 1, 10) for r in flagged) * 3)
        points.append((detection_points, f"{len(flagged)} provider(s) reported malicious evidence"))
    confidence = max((r.confidence or 0 for r in successful), default=0)
    if confidence:
        points.append((round(confidence * .20), f"Highest reputation confidence was {confidence}%"))
    if len(flagged) >= 2:
        agreement = min(15, 5 + (len(flagged) - 2) * 5)
        points.append((agreement, "Multiple independent providers agreed on malicious activity"))
    if any("known_exploited" in r.categories for r in successful):
        points.append((40, "CVE appears in CISA's Known Exploited Vulnerabilities catalogue"))
    if any(r.observed_at for r in flagged):
        points.append((5, "Malicious intelligence includes a dated observation"))
    score = min(100, sum(value for value, _ in points))
    explanations = [f"+{value}: {reason}" for value, reason in points]
    if not explanations:
        explanations = ["+0: No provider returned a positive malicious signal"]
    if len(successful) < len(results):
        explanations.append("Partial coverage: some provider checks were unavailable; the score uses available evidence only.")
    return score, verdict_for(score), explanations

