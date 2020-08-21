use percent_encoding::{utf8_percent_encode, AsciiSet, PercentEncode, NON_ALPHANUMERIC};

// based on https://docs.python.org/3/library/urllib.parse.html#urllib.parse.quote
// which defines what the Python client does here
const NOT_ENCODED: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'_')
    .remove(b'.')
    .remove(b'-')
    .remove(b'~');

pub(crate) fn urlencode<'a>(input: &'a str) -> PercentEncode<'a> {
    utf8_percent_encode(input, NOT_ENCODED)
}

#[cfg(test)]
mod test {
    use super::*;

    macro_rules! urlencode_tests {
    ($($name:ident: $input:expr, $output:expr,)*) => {
    $(
        #[test]
        fn $name() {
            assert_eq!(&urlencode($input).to_string(), $output);
        }
    )*
    }
}

    urlencode_tests! {
        unencoded: "abc-ABC_123.tilde~..", "abc-ABC_123.tilde~..",
        slashes: "abc/def", "abc%2Fdef",
        spaces: "abc def", "abc%20def",
        control: "abc\ndef", "abc%0Adef",
    }
}
