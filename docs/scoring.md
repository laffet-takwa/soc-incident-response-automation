# Scoring logic

For each IOC, source values are normalized to a 0–100 signal and combined as a weighted mean: VT malicious ratio 50%, AbuseIPDB abuse-confidence score 30%, OTX pulse count mapped to `min(100, 25 × count)` at 20%. Only valid available source signals participate; weights are renormalized to the available total. A failure or timeout is unknown and never becomes a zero verdict. If no usable signal is available, score is null.

Alert score is the maximum IOC score. This preserves a high-risk single IOC in a mixed alert. Severity maps to TheHive's integer severity range: <40=1, 40–69.99=2, 70–89.99=3, >=90=4. Null maps to 1 solely to satisfy the alert schema; tags and description state that the IOC is unscored.

This heuristic is neither a calibrated probability nor a decision rule. Validate weights against a labeled dataset before operational use. OTX pulse count measures community context and may include duplicated, stale, or low-quality pulses. VT ratio denominator is the returned analysis statistics total. Different source availability across IOC types affects coverage, which must be shown with every score.
