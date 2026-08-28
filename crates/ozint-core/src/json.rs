use serde::Serializer;

/// Serialize an `f64` the way `JSON.stringify` does.
///
/// `serde_json` writes an integral f64 as `0.0`; JavaScript writes `0`. Both
/// parse to the same number, so this only matters where a response is diffed
/// byte-for-byte against the captured Next.js output — which is exactly how this
/// migration is verified.
pub fn js_number<S: Serializer>(value: &f64, serializer: S) -> Result<S::Ok, S::Error> {
    // 2^53: beyond it an i64 round-trip would lose precision, so keep the float.
    const MAX_EXACT_INT: f64 = 9_007_199_254_740_992.0;
    if value.is_finite() && value.fract() == 0.0 && value.abs() < MAX_EXACT_INT {
        serializer.serialize_i64(*value as i64)
    } else {
        serializer.serialize_f64(*value)
    }
}

#[cfg(test)]
mod tests {
    use serde::Serialize;

    #[derive(Serialize)]
    struct Holder {
        #[serde(serialize_with = "super::js_number")]
        value: f64,
    }

    fn json(value: f64) -> String {
        serde_json::to_string(&Holder { value }).unwrap()
    }

    #[test]
    fn integral_values_lose_the_decimal_point() {
        assert_eq!(json(0.0), r#"{"value":0}"#);
        assert_eq!(json(42.0), r#"{"value":42}"#);
        assert_eq!(json(-7.0), r#"{"value":-7}"#);
    }

    #[test]
    fn fractional_values_are_untouched() {
        assert_eq!(json(0.5), r#"{"value":0.5}"#);
        assert_eq!(json(-1.25), r#"{"value":-1.25}"#);
    }

    #[test]
    fn values_beyond_exact_integer_range_stay_floats() {
        assert_eq!(json(1e300), r#"{"value":1e+300}"#);
    }
}
