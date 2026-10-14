"""Local prototype API for email analysis."""

from importlib import import_module
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, StrictStr


PROJECT_NAME = "AI-Powered Email Threat Detection and Forensic Intelligence Platform"
MAX_EMAIL_BYTES = 1024 * 1024
MODEL_PATH = Path(__file__).resolve().parent / "models" / "email_spam_model.joblib"

_ANALYSIS_INTERFACES = {
    "email_analyzer": ("analyze_email_message",),
    "header_analyzer": ("analyze_email",),
    "ip_geolocation": ("lookup_ip_location",),
    "threat_intelligence": ("analyze_threat_indicators",),
    "risk_assessment": ("build_risk_assessment",),
    "forensic_report": ("format_forensic_report",),
}

app = FastAPI(
    title=PROJECT_NAME,
    description="A local prototype for email spam and forensic indicator review.",
    debug=False,
)

# Permit only the documented loopback development server origin.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:5500"],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


class AnalyzeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    raw_email: StrictStr


def analyze_email_message(raw_email: str) -> dict[str, Any]:
    """Load and invoke the existing unified analyzer on demand."""
    analyzer = import_module("email_analyzer").analyze_email_message
    return analyzer(raw_email)


def _module_status() -> dict[str, bool]:
    status: dict[str, bool] = {}
    for module_name, function_names in _ANALYSIS_INTERFACES.items():
        try:
            module = import_module(module_name)
            status[module_name] = all(
                callable(getattr(module, function_name, None))
                for function_name in function_names
            )
        except Exception:
            status[module_name] = False
    return status


def _model_status(modules: dict[str, bool]) -> dict[str, bool]:
    exists = MODEL_PATH.is_file()
    loadable = False
    if exists and modules.get("email_analyzer", False):
        try:
            analyzer_module = import_module("email_analyzer")
            loader = getattr(analyzer_module, "_load_pipeline", None)
            if callable(loader):
                loader()
                loadable = True
        except Exception:
            loadable = False
    return {"exists": exists, "loadable": loadable}


def _analysis_response(result: Any) -> dict[str, Any]:
    """Expose existing analysis values without returning raw email headers."""
    if not isinstance(result, dict):
        raise TypeError("Analyzer returned an invalid result.")

    required_keys = (
        "ml_prediction",
        "ml_label",
        "forensic_findings",
        "forensic_summary",
        "threat_intelligence_findings",
        "threat_intelligence",
        "overall_assessment",
        "risk_assessment",
        "forensic_report",
        "limitations",
    )
    if any(key not in result for key in required_keys):
        raise KeyError("Analyzer result is missing required fields.")

    threat_result = result["threat_intelligence"]
    assessment = result["risk_assessment"]
    header_fields = result.get("header_fields")
    if (
        not isinstance(threat_result, dict)
        or not isinstance(assessment, dict)
        or not isinstance(header_fields, dict)
    ):
        raise TypeError("Analyzer returned malformed structured results.")
    if "reputation" not in threat_result or "ip_information" not in assessment:
        raise KeyError("Analyzer result is missing provider status information.")

    return {
        "ml_prediction": result["ml_prediction"],
        "ml_label": result["ml_label"],
        "forensic_findings": result["forensic_findings"],
        "forensic_summary": result["forensic_summary"],
        "ip_information": assessment["ip_information"],
        "threat_intelligence_findings": result["threat_intelligence_findings"],
        "threat_reputation": threat_result["reputation"],
        "sender_addresses": header_fields.get("sender_addresses", {}),
        "authentication_checks": header_fields.get("authentication_checks", []),
        "detected_urls": threat_result.get("urls", []),
        "overall_assessment": result["overall_assessment"],
        "risk_assessment": assessment,
        "forensic_report": result["forensic_report"],
        "limitations": result["limitations"],
    }


@app.exception_handler(RequestValidationError)
async def request_validation_error_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    """Return validation errors without reflecting submitted request values."""
    error_types = {error.get("type") for error in exc.errors()}
    if "json_invalid" in error_types:
        return JSONResponse(
            status_code=400,
            content={"detail": "Malformed JSON request."},
        )
    return JSONResponse(
        status_code=422,
        content={
            "detail": (
                "Invalid request. Provide a non-empty raw_email string no larger "
                "than 1 MiB."
            )
        },
    )


@app.get("/")
async def root() -> dict[str, str]:
    return {"project": PROJECT_NAME, "status": "running"}


@app.get("/health")
async def health() -> dict[str, Any]:
    modules = _module_status()
    model = _model_status(modules)
    healthy = model["loadable"] and all(modules.values())
    return {
        "status": "ok" if healthy else "degraded",
        "model": model,
        "analysis_modules": modules,
        "providers": {
            "ip_geolocation": "not_configured",
            "threat_reputation": "not_configured",
        },
    }


@app.post("/analyze")
async def analyze(request: AnalyzeRequest) -> JSONResponse:
    raw_email = request.raw_email
    if not raw_email.strip():
        return JSONResponse(
            status_code=422,
            content={"detail": "raw_email must not be empty."},
        )
    try:
        email_size = len(raw_email.encode("utf-8"))
    except UnicodeEncodeError:
        return JSONResponse(
            status_code=422,
            content={"detail": "raw_email must contain valid UTF-8 text."},
        )
    if email_size > MAX_EMAIL_BYTES:
        return JSONResponse(
            status_code=413,
            content={"detail": "raw_email exceeds the 1 MiB size limit."},
        )

    try:
        result = analyze_email_message(raw_email)
        response = _analysis_response(result)
        return JSONResponse(content=response)
    except Exception:
        return JSONResponse(
            status_code=500,
            content={"detail": "Email analysis failed. No message content was stored."},
        )
