
"""
Explainable phishing risk engine.

The engine combines:
- Sender analysis
- Email content analysis
- URL analysis
- Attachment analysis
- Header analysis
- Domain analysis
- Optional ML probability

It also provides calculate_risk() as a compatibility
function for the project's existing tests.
"""


def _safe_score(value, default=0):
    """
    Convert a value safely to a numeric score.
    """

    try:
        return float(value)
    except (
        TypeError,
        ValueError,
    ):
        return float(default)


def _extract_reasons(result):
    """
    Extract reasons from an analyzer result.
    """

    if not isinstance(result, dict):
        return []

    reasons = result.get(
        "reasons",
        [],
    )

    if not isinstance(
        reasons,
        list,
    ):
        return [str(reasons)]

    return [
        str(reason)
        for reason in reasons
        if reason
    ]


def _extract_indicators(result):
    """
    Extract indicators from an analyzer result.
    """

    if not isinstance(result, dict):
        return []

    indicators = result.get(
        "indicators",
        [],
    )

    if not isinstance(
        indicators,
        list,
    ):
        return [str(indicators)]

    return indicators


def _get_ml_probability(
    ml_probability=None,
    ml_result=None,
):
    """
    Get ML phishing probability from either:
    - direct ml_probability argument
    - ml_result dictionary
    """

    if ml_probability is not None:
        return max(
            0.0,
            min(
                1.0,
                _safe_score(
                    ml_probability
                ),
            ),
        )

    if isinstance(
        ml_result,
        dict,
    ):
        probability = ml_result.get(
            "phishing_probability"
        )

        if probability is not None:
            return max(
                0.0,
                min(
                    1.0,
                    _safe_score(
                        probability
                    ),
                ),
            )

    return None


def _url_score(url_results):
    """
    Calculate the contribution from URL analysis.
    """

    if not isinstance(
        url_results,
        list,
    ):
        return 0

    maximum = 0

    for item in url_results:

        if not isinstance(
            item,
            dict,
        ):
            continue

        score = _safe_score(
            item.get(
                "risk_score",
                0,
            )
        )

        maximum = max(
            maximum,
            score,
        )

    return maximum


def calculate_phishing_score(
    sender_result,
    content_result,
    url_results,
    attachment_result,
    header_result=None,
    domain_result=None,
    ml_probability=None,
):
    """
    Calculate the final phishing risk score.

    Rule-based score is calculated first.
    ML can contribute up to 30 additional points.
    """

    sender_result = (
        sender_result
        if isinstance(
            sender_result,
            dict,
        )
        else {}
    )

    content_result = (
        content_result
        if isinstance(
            content_result,
            dict,
        )
        else {}
    )

    attachment_result = (
        attachment_result
        if isinstance(
            attachment_result,
            dict,
        )
        else {}
    )

    header_result = (
        header_result
        if isinstance(
            header_result,
            dict,
        )
        else {}
    )

    domain_result = (
        domain_result
        if isinstance(
            domain_result,
            dict,
        )
        else {}
    )

    if not isinstance(
        url_results,
        list,
    ):
        url_results = []

    score = 0
    reasons = []

    # ---------------------------------------------------------
    # Sender
    # ---------------------------------------------------------

    sender_score = _safe_score(
        sender_result.get(
            "sender_risk_score",
            sender_result.get(
                "risk_score",
                0,
            ),
        )
    )

    if sender_score >= 10:
        score += 12

        reasons.append(
            "Suspicious sender characteristics contributed to the score."
        )

    # Include sender analyzer reasons.
    reasons.extend(
        _extract_reasons(
            sender_result
        )
    )

    # ---------------------------------------------------------
    # Content
    # ---------------------------------------------------------

    counts = content_result.get(
        "counts",
        {},
    )

    if not isinstance(
        counts,
        dict,
    ):
        counts = {}

    urgency = _safe_score(
        counts.get(
            "urgency",
            0,
        )
    )

    credential_request = _safe_score(
        counts.get(
            "credential_request",
            0,
        )
    )

    fear = _safe_score(
        counts.get(
            "fear",
            0,
        )
    )

    financial_pressure = _safe_score(
        counts.get(
            "financial_pressure",
            0,
        )
    )

    if urgency > 0:
        score += 10
        reasons.append(
            "Urgency language detected."
        )

    if credential_request > 0:
        score += 18
        reasons.append(
            "Credential/account verification language detected."
        )

    if fear > 0:
        score += 10
        reasons.append(
            "Threat/fear language detected."
        )

    if financial_pressure > 0:
        score += 7
        reasons.append(
            "Financial-pressure language detected."
        )

    if content_result.get(
        "generic_greeting"
    ):
        score += 3
        reasons.append(
            "Generic greeting detected."
        )

    reasons.extend(
        _extract_reasons(
            content_result
        )
    )

    # ---------------------------------------------------------
    # URLs
    # ---------------------------------------------------------

    highest_url_score = _url_score(
        url_results
    )

    if highest_url_score >= 20:
        score += 20

        reasons.append(
            "A high-risk URL indicator was detected."
        )

    # ---------------------------------------------------------
    # Attachment
    # ---------------------------------------------------------

    attachment_score = _safe_score(
        attachment_result.get(
            "risk_score",
            0,
        )
    )

    if attachment_score >= 20:
        score += 20

        reasons.append(
            "Suspicious attachment filename pattern detected."
        )

    reasons.extend(
        _extract_reasons(
            attachment_result
        )
    )

    # ---------------------------------------------------------
    # Headers
    # ---------------------------------------------------------

    header_score = _safe_score(
        header_result.get(
            "risk_score",
            0,
        )
    )

    if header_score > 0:
        contribution = min(
            20,
            int(header_score),
        )

        score += contribution

        findings = header_result.get(
            "findings",
            [],
        )

        if isinstance(
            findings,
            list,
        ):
            for finding in findings:

                if isinstance(
                    finding,
                    dict,
                ):
                    description = finding.get(
                        "description"
                    )

                    severity = finding.get(
                        "severity",
                        "info",
                    )

                    if (
                        description
                        and severity != "info"
                    ):
                        reasons.append(
                            str(description)
                        )

                elif finding:
                    reasons.append(
                        str(finding)
                    )

    # ---------------------------------------------------------
    # Domain
    # ---------------------------------------------------------

    domain_score = _safe_score(
        domain_result.get(
            "risk_score",
            0,
        )
    )

    if domain_score > 0:

        contribution = min(
            10,
            int(domain_score),
        )

        score += contribution

        findings = domain_result.get(
            "findings",
            [],
        )

        if isinstance(
            findings,
            list,
        ):
            for finding in findings:

                if isinstance(
                    finding,
                    dict,
                ):
                    description = finding.get(
                        "description"
                    )

                    severity = finding.get(
                        "severity",
                        "info",
                    )

                    if (
                        description
                        and severity != "info"
                    ):
                        reasons.append(
                            str(description)
                        )

                elif finding:
                    reasons.append(
                        str(finding)
                    )

    # ---------------------------------------------------------
    # Rule score
    # ---------------------------------------------------------

    rule_score = min(
        100,
        int(score),
    )

    # ---------------------------------------------------------
    # Machine learning
    # ---------------------------------------------------------

    probability = _get_ml_probability(
        ml_probability=ml_probability
    )

    ml_contribution = 0

    if probability is not None:

        # Maximum ML contribution = 30 points.
        ml_contribution = min(
            30,
            round(
                probability * 30
            ),
        )

        reasons.append(
            "ML model contribution: "
            f"{probability:.0%} phishing probability "
            f"(capped contribution: "
            f"{ml_contribution} points)."
        )

    final_score = min(
        100,
        rule_score + ml_contribution,
    )

    # ---------------------------------------------------------
    # Classification
    # ---------------------------------------------------------

    if final_score <= 20:

        classification = (
            "LOW RISK"
        )

    elif final_score <= 40:

        classification = (
            "MODERATE RISK"
        )

    elif final_score <= 70:

        classification = (
            "SUSPICIOUS"
        )

    else:

        classification = (
            "HIGH RISK / LIKELY PHISHING"
        )

    # ---------------------------------------------------------
    # Recommendations
    # ---------------------------------------------------------

    recommendations = [
        "Do not click unexpected links.",
        "Do not open unexpected attachments.",
        "Verify the sender through a trusted channel.",
        "Use the organization's official website or application directly.",
        "Review authentication results when available.",
        "Report suspicious email to your security team when appropriate.",
    ]

    return {
        "risk_score": final_score,
        "rule_score": rule_score,
        "ml_contribution": ml_contribution,
        "classification": classification,
        "reasons": reasons,
        "recommendations": recommendations,
    }


def calculate_risk(
    sender_result=None,
    content_result=None,
    url_results=None,
    attachment_result=None,
    header_result=None,
    domain_result=None,
    ml_probability=None,
    ml_result=None,
):
    """
    Compatibility wrapper used by the project's tests.

    Supports calls such as:

        calculate_risk(
            sender_result={...},
            ml_result={
                "phishing_probability": 0.90
            },
        )

    It also supports the full analyzer format.
    """

    sender_result = (
        sender_result
        if isinstance(
            sender_result,
            dict,
        )
        else {}
    )

    content_result = (
        content_result
        if isinstance(
            content_result,
            dict,
        )
        else {}
    )

    attachment_result = (
        attachment_result
        if isinstance(
            attachment_result,
            dict,
        )
        else {}
    )

    if url_results is None:
        url_results = []

    # ---------------------------------------------------------
    # Support ML result dictionary used by tests.
    # ---------------------------------------------------------

    probability = _get_ml_probability(
        ml_probability=ml_probability,
        ml_result=ml_result,
    )

    # ---------------------------------------------------------
    # Compatibility with the simpler test structure.
    #
    # Example:
    # sender_result={
    #     "risk_score": 10,
    #     "reasons": ["Suspicious sender"],
    #     "indicators": ["suspicious_sender"],
    # }
    #
    # If no other analyzer data is supplied, use the sender
    # risk score directly as the base rule score.
    # ---------------------------------------------------------

    simple_sender_score = _safe_score(
        sender_result.get(
            "risk_score",
            0,
        )
    )

    has_full_sender_score = (
        "sender_risk_score"
        in sender_result
    )

    if (
        simple_sender_score
        and not has_full_sender_score
        and not content_result
        and not attachment_result
        and not url_results
        and not header_result
        and not domain_result
    ):

        rule_score = min(
            100,
            int(simple_sender_score),
        )

        ml_contribution = 0

        if probability is not None:
            ml_contribution = min(
                30,
                round(
                    probability * 30
                ),
            )

        final_score = min(
            100,
            rule_score
            + ml_contribution,
        )

        if final_score <= 20:
            classification = (
                "LOW RISK"
            )
        elif final_score <= 40:
            classification = (
                "MODERATE RISK"
            )
        elif final_score <= 70:
            classification = (
                "SUSPICIOUS"
            )
        else:
            classification = (
                "HIGH RISK / LIKELY PHISHING"
            )

        reasons = _extract_reasons(
            sender_result
        )

        if probability is not None:
            reasons.append(
                "ML model contribution: "
                f"{probability:.0%} phishing probability "
                f"(capped contribution: "
                f"{ml_contribution} points)."
            )

        return {
            "risk_score": final_score,
            "rule_score": rule_score,
            "ml_probability": probability,
            "ml_contribution": ml_contribution,
            "classification": classification,
            "reasons": reasons,
            "indicators": _extract_indicators(
                sender_result
            ),
            "recommendations": [
                "Do not click unexpected links.",
                "Do not open unexpected attachments.",
                "Verify the sender through a trusted channel.",
            ],
        }

    # Full analyzer compatibility.
    return calculate_phishing_score(
        sender_result=sender_result,
        content_result=content_result,
        url_results=url_results,
        attachment_result=attachment_result,
        header_result=header_result,
        domain_result=domain_result,
        ml_probability=probability,
    )
