import sys
from pathlib import Path

core_src = Path(__file__).parent.parent / "src"
sys.path.insert(0, str(core_src))

from vexa.common.models import (
    CloudProvider,
    ScanMode,
    JobStatus,
    Job,
    JobResult,
    Finding,
    EnhancedFinding,
    KiroEnhancedFinding,
    AzureEnhancedFinding,
    Threat,
    ThreatModel,
    DriftProperty,
    DriftFinding,
    ScanResult,
)
from vexa.common.config_manager import (
    ScannersConfig,
    QualityGateConfig,
    AIConfig,
    ReportsConfig,
    VexaConfig,
)


def to_camel_case(snake_str):
    components = snake_str.split("_")
    return components[0] + "".join(x.title() for x in components[1:])


# Legacy mapping for VS Code backwards compatibility
LEGACY_MAPPING = {
    "file_path": "filePath",
    "line_start": "line",
    "line_end": "endLine",
    "remediation_guidance": "remediationDescription",
    "fp_explanation": "falsePositiveReason",
    "false_positive_confidence": "confidenceScore",
    "owasp_category": "owaspCategories",
    "nist_controls": "nistCategories",
    "mitre_attack_id": "mitreAttack",
}


def type_mapping(py_type, refs=None):
    if py_type == "string":
        return "string"
    if py_type in ["integer", "number"]:
        return "number"
    if py_type == "boolean":
        return "boolean"
    if py_type == "array":
        return "any[]"
    return "any"


def generate_ts():
    models = [
        Finding,
        EnhancedFinding,
        KiroEnhancedFinding,
        AzureEnhancedFinding,
        Job,
        JobResult,
        Threat,
        ThreatModel,
        DriftProperty,
        DriftFinding,
        ScanResult,
        ScannersConfig,
        QualityGateConfig,
        AIConfig,
        ReportsConfig,
        VexaConfig,
    ]

    enums = {
        "CloudProvider": CloudProvider,
        "ScanMode": ScanMode,
        "ScanStatus": JobStatus,
    }

    ts_content = "/**\n * Vexa VS Code Extension — Type Definitions\n"
    ts_content += " * AUTO-GENERATED from Python Pydantic Models\n */\n\n"

    for enum_name, enum_class in enums.items():
        ts_content += f"export enum {enum_name} {{\n"
        for item in enum_class:
            ts_content += f"    {item.name.capitalize()} = '{item.value}',\n"
        ts_content += "}\n\n"

    ts_content += "export enum FindingSeverity {\n"
    ts_content += "    Critical = 'critical',\n"
    ts_content += "    High = 'high',\n"
    ts_content += "    Medium = 'medium',\n"
    ts_content += "    Low = 'low',\n"
    ts_content += "    Info = 'info'\n"
    ts_content += "}\n\n"

    for model in models:
        schema = model.model_json_schema()
        name = schema.get("title", model.__name__)
        ts_content += f"export interface {name} {{\n"

        # Inject ruleId for legacy compat if it's a finding
        if name in [
            "Finding",
            "EnhancedFinding",
            "KiroEnhancedFinding",
            "AzureEnhancedFinding",
        ]:
            ts_content += "    ruleId: string;\n"
            ts_content += "    column?: number;\n"
            ts_content += "    endColumn?: number;\n"
            ts_content += "    rawData?: any;\n"
            ts_content += "    confidence?: string;\n"

        properties = schema.get("properties", {})
        required = schema.get("required", [])

        for prop_name, prop_data in properties.items():
            if prop_name in [
                "total_findings",
                "findings_by_severity",
                "findings_by_scanner",
            ]:
                continue

            # Legacy overwrite
            ts_prop_name = LEGACY_MAPPING.get(prop_name, to_camel_case(prop_name))

            is_req = prop_name in required
            # Force endLine to be optional for TS compat
            if ts_prop_name == "endLine":
                is_req = False
            req_flag = "" if is_req else "?"

            # Simple type mapping
            ts_type = "any"
            if "type" in prop_data:
                ts_type = type_mapping(prop_data["type"])
                if prop_data["type"] == "array" and "items" in prop_data:
                    items = prop_data["items"]
                    if "$ref" in items:
                        ts_type = f"{items['$ref'].split('/')[-1]}[]"
                    elif "type" in items:
                        ts_type = f"{type_mapping(items['type'])}[]"
            elif "$ref" in prop_data:
                ts_type = prop_data["$ref"].split("/")[-1]
            elif "anyOf" in prop_data:
                types = []
                for t in prop_data["anyOf"]:
                    if "$ref" in t:
                        types.append(t["$ref"].split("/")[-1])
                    elif "type" in t and t["type"] != "null":
                        types.append(type_mapping(t["type"]))
                if types:
                    ts_type = " | ".join(set(types))

            if prop_name == "severity":
                ts_type = "FindingSeverity"
            elif prop_name == "status":
                ts_type = "ScanStatus"
            elif prop_name == "cloud_provider":
                ts_type = "CloudProvider"

            ts_content += f"    {ts_prop_name}{req_flag}: {ts_type};\n"

        ts_content += "}\n\n"

    ts_content += """
export interface ScanRequest {
    path: string;
    scanners?: string[];
    mode?: ScanMode;
    cloudProvider?: string;
}

export interface ScanStatusResponse {
    jobId: string;
    status: ScanStatus;
    progress: number;
    currentScanner?: string;
    message?: string;
    error?: string;
}

export interface ScanSummary {
    totalFindings: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    scannersRun: string[];
    scannersFailed: string[];
    durationSeconds: number;
}

export interface ScannerInfo {
    name: string;
    installed: boolean;
    version?: string;
    supportedLanguages: string[];
}

export interface BaselineSuppression {
    ruleId: string;
    file: string;
    line: number;
    reason: string;
    suppressedBy: string;
    suppressedAt: string;
}

export interface BaselineFile {
    version: string;
    suppressions: BaselineSuppression[];
}

export interface ScanHistoryEntry {
    jobId: string;
    timestamp: string;
    path: string;
    totalFindings: number;
    summary: ScanSummary;
}
"""
    return ts_content


if __name__ == "__main__":
    out_dir = Path(__file__).parent.parent.parent / "vscode-extension" / "src" / "types"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / "index.ts"

    ts_code = generate_ts()
    with open(out_file, "w", encoding="utf-8") as f:
        f.write(ts_code)
    print(f"Successfully generated TypeScript interfaces at {out_file}")
