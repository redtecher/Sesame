from sesame.domain.report import DiagnosisHypothesis


def rank_hypotheses(mismatches, primitive_plans):
    hypotheses = []
    for mismatch, primitive in zip(mismatches, primitive_plans, strict=False):
        hypotheses.append(
            DiagnosisHypothesis(
                title=mismatch.title,
                mismatch_layer=mismatch.layer.value,
                primitives=[primitive],
                rationale=mismatch.description,
                evidence=mismatch.evidence,
                verification_steps=primitive.verification_steps,
                confidence=mismatch.confidence,
            )
        )
    return sorted(hypotheses, key=lambda h: h.confidence, reverse=True)

