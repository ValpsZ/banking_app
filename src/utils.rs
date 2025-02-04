use actix_web::{body::BoxBody, web, HttpResponse};

pub(crate) fn server_error(dev_msg: &str, app_mode: &str) -> HttpResponse<BoxBody> {
    let message = match app_mode {
        "dev" => dev_msg.to_string(),
        _ => "".to_string(),
    };

    return HttpResponse::InternalServerError().body(message);
}

pub(crate) fn forbidden(dev_msg: &str, app_mode: &str) -> HttpResponse<BoxBody> {
    let message = match app_mode {
        "dev" => dev_msg.to_string(),
        _ => "".to_string(),
    };

    return HttpResponse::Forbidden().body(message);
}
