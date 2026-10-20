// Breach threshold for the Mahalanobis drift score. MUST equal CHI2_99_DF3 in
// seismograph/drift_detector.py (sqrt of the chi-square 99% quantile, df=3);
// tests/contract/test_ui_threshold.py fails if the two differ.
export const DRIFT_THRESHOLD = 3.368;
