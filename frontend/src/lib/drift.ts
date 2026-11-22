// Breach threshold for the Mahalanobis drift score. MUST equal CHI2_99_DF3 in
// seismograph/drift_detector.py (sqrt of the chi-square 99% quantile, df=3);
// tests/contract/test_ui_threshold.py fails if the two differ.
export const DRIFT_THRESHOLD = 3.368;

/** A point's own threshold when it is a finite positive number, else the constant (recorded replays carry none). */
export function pointThreshold(threshold: unknown): number {
  return typeof threshold === "number" && Number.isFinite(threshold) && threshold > 0 ? threshold : DRIFT_THRESHOLD;
}

/** The threshold line: the LATEST point's threshold when valid, else the constant. */
export function latestThreshold(points: ReadonlyArray<{ threshold?: number }>): number {
  return pointThreshold(points.length ? points[points.length - 1].threshold : undefined);
}
