use actix_web::{body::BoxBody, web, HttpResponse};

pub(crate) fn server_error(dev_msg: &str, app_mode: web::Data<String>) -> HttpResponse<BoxBody> {
    let message = match app_mode.to_string().as_str() {
        "dev" => dev_msg.to_string(),
        _ => "".to_string(),
    };

    return HttpResponse::InternalServerError().body(message);
}

pub(crate) fn forbidden(dev_msg: &str, app_mode: web::Data<String>) -> HttpResponse<BoxBody> {
    let message = match app_mode.to_string().as_str() {
        "dev" => dev_msg.to_string(),
        _ => "".to_string(),
    };

    return HttpResponse::Forbidden().body(message);
}
