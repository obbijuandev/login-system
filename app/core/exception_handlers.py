from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

DEFAULT_HTTP_DETAILS = {
    405: {
        "en": "Method Not Allowed",
        "es": "Método no permitido",
    }
}

VALIDATION_MESSAGE_BY_TYPE = {
    "missing": "Campo requerido",
    "string_type": "Debe ser una cadena de texto válida",
    "int_type": "Debe ser un número entero válido",
    "int_parsing": "Debe ser un número entero válido",
    "float_type": "Debe ser un número decimal válido",
    "float_parsing": "Debe ser un número decimal válido",
    "bool_type": "Debe ser un valor booleano válido",
    "bool_parsing": "Debe ser un valor booleano válido",
    "list_type": "Debe ser una lista válida",
    "dict_type": "Debe ser un objeto válido",
    "json_invalid": "El JSON enviado no es válido",
}


def _translate_default_http_detail(status_code: int, detail: Any) -> Any:
    if not isinstance(detail, str):
        return detail

    default_detail = DEFAULT_HTTP_DETAILS.get(status_code)
    if default_detail and detail == default_detail["en"]:
        return default_detail["es"]

    return detail


def _translate_validation_message(error: dict[str, Any]) -> str:
    error_type = error.get("type")
    if error_type == "value_error":
        original_error = error.get("ctx", {}).get("error")
        if isinstance(original_error, ValueError) and original_error.args:
            return str(original_error.args[0])

        message = error.get("msg", "")
        prefix = "Value error, "
        if message.startswith(prefix):
            return message[len(prefix) :]
        return message

    return VALIDATION_MESSAGE_BY_TYPE.get(
        error_type, error.get("msg", "Entrada inválida")
    )


def _translate_validation_error(error: dict[str, Any]) -> dict[str, Any]:
    translated_error = {key: value for key, value in error.items() if key != "url"}
    context = translated_error.get("ctx")
    if isinstance(context, dict):
        translated_error["ctx"] = {
            key: str(value) if isinstance(value, BaseException) else value
            for key, value in context.items()
        }
    translated_error["msg"] = _translate_validation_message(error)
    return translated_error


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(request: Request, exc: StarletteHTTPException):
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "detail": _translate_default_http_detail(exc.status_code, exc.detail)
            },
            headers=exc.headers,
        )

    @app.exception_handler(RequestValidationError)
    async def request_validation_exception_handler(
        request: Request,
        exc: RequestValidationError,
    ):
        return JSONResponse(
            status_code=422,
            content={
                "detail": [_translate_validation_error(error) for error in exc.errors()]
            },
        )
