use custom_error::custom_error;

use url::ParseError;

custom_error! {
    pub CrowdSecApiError
    RequestFailed{error: reqwest::Error} = "CrowdSec API call failed. Error: {error}",
    ResponseBad{status_code: reqwest::StatusCode} = "CrowdSec API call not successful. Status code: {status_code}",
    ResponseParsingFailed{error: String} = "CrowdSec response parsing failed. Error: {error}",
    UrlParsingFailed{error: ParseError} = "CrowdSec url parsing failed. Error: {error}",
}

custom_error! {
    pub TraefikError
    BadHeaders = "Bad Forward-Request headers.",
}
