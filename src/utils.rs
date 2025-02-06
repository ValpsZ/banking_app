use actix_web::{body::BoxBody, HttpResponse, HttpResponseBuilder};

pub(crate) fn respond(
    mut response_builder: HttpResponseBuilder,
    dev_msg: &str,
    prod_msg: &str,
    app_mode: String,
) -> HttpResponse<BoxBody> {
    let message = match app_mode.as_str() {
        "dev" => dev_msg.to_string(),
        _ => prod_msg.to_string(),
    };

    return response_builder.body(message);
}
