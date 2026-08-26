from fastapi import FastAPI
from fastapi.responses import JSONResponse

import hashlib
import json
import math
import re


app = FastAPI()

SAFE_INT_MAX = 9007199254740991

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

FREEZES = {}


# ============================================================
# HELPERS
# ============================================================

def utf8_key(value):
    return value.encode("utf-8")


def unique_sorted(codes):
    return sorted(
        set(codes),
        key=utf8_key
    )


def compact_json(value):
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":")
    )


def safe_int(value):
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and 0 <= value <= SAFE_INT_MAX
    )


def finite(value):
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(float(value))
    )


def nonnegative_finite(value):
    return finite(value) and float(value) >= 0


def valid_nonempty_string(value, max_len=None):
    if not isinstance(value, str):
        return False

    if value == "":
        return False

    if max_len is not None and len(value) > max_len:
        return False

    return True


def valid_sha256(value):
    return (
        isinstance(value, str)
        and SHA256_RE.fullmatch(value) is not None
    )


def fingerprint(payload):
    return hashlib.sha256(
        compact_json(payload).encode("utf-8")
    ).hexdigest()


# ============================================================
# BUILD INVENTORY
# ============================================================

def build_inventory(files):
    if not isinstance(files, dict):
        return [], None, None, False

    if len(files) == 0:
        return [], None, None, False

    inventory = []
    seen = set()

    for filename, content in files.items():

        if not isinstance(filename, str):
            return [], None, None, False

        if filename == "":
            return [], None, None, False

        if filename in seen:
            return [], None, None, False

        seen.add(filename)

        if not isinstance(content, str):
            return [], None, None, False

        raw = content.encode("utf-8")

        inventory.append({
            "name": filename,
            "bytes": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest()
        })

    inventory.sort(
        key=lambda x: utf8_key(x["name"])
    )

    total_bytes = sum(
        item["bytes"]
        for item in inventory
    )

    package_digest = hashlib.sha256(
        compact_json(inventory).encode("utf-8")
    ).hexdigest()

    return (
        inventory,
        total_bytes,
        package_digest,
        True
    )


# ============================================================
# VALIDATE STORED INVENTORY
# ============================================================

def validate_inventory(inventory):
    if not isinstance(inventory, list):
        return False, None, None

    if len(inventory) == 0:
        return False, None, None

    seen = set()
    rebuilt = []
    total = 0

    for item in inventory:

        if not isinstance(item, dict):
            return False, None, None

        required = {
            "name",
            "bytes",
            "sha256"
        }

        if not required.issubset(item.keys()):
            return False, None, None

        name = item["name"]
        byte_count = item["bytes"]
        sha = item["sha256"]

        if not isinstance(name, str) or name == "":
            return False, None, None

        if name in seen:
            return False, None, None

        seen.add(name)

        if not safe_int(byte_count):
            return False, None, None

        if not valid_sha256(sha):
            return False, None, None

        if total > SAFE_INT_MAX - byte_count:
            return False, None, None

        total += byte_count

        rebuilt.append({
            "name": name,
            "bytes": byte_count,
            "sha256": sha
        })

    rebuilt.sort(
        key=lambda x: utf8_key(x["name"])
    )

    digest = hashlib.sha256(
        compact_json(rebuilt).encode("utf-8")
    ).hexdigest()

    return True, total, digest


# ============================================================
# FREEZE
# ============================================================

def perform_freeze(payload):

    required = {
        "phase",
        "freezeId",
        "calibrationDigest",
        "tokenizerDigest",
        "allowedUnsupportedReasons",
        "candidates"
    }

    if not required.issubset(payload.keys()):
        return None, 400

    if payload["phase"] != "freeze":
        return None, 400

    freeze_id = payload["freezeId"]

    if not valid_nonempty_string(
        freeze_id,
        128
    ):
        return None, 400

    calibration_digest = payload["calibrationDigest"]
    tokenizer_digest = payload["tokenizerDigest"]

    if not valid_nonempty_string(
        calibration_digest
    ):
        return None, 400

    if not valid_nonempty_string(
        tokenizer_digest
    ):
        return None, 400

    allowed = payload[
        "allowedUnsupportedReasons"
    ]

    if not isinstance(allowed, list):
        return None, 400

    if any(
        not valid_nonempty_string(x)
        for x in allowed
    ):
        return None, 400

    if len(set(allowed)) != len(allowed):
        return None, 400

    candidates = payload["candidates"]

    if not isinstance(candidates, list):
        return None, 400

    # Explicitly required by the task.
    if len(candidates) == 0:
        return None, 400

    seen_names = set()
    output = []

    for candidate in candidates:

        if not isinstance(candidate, dict):
            return None, 400

        required_candidate = {
            "name",
            "files",
            "loadable",
            "calibrationDigest",
            "tokenizerDigest"
        }

        if not required_candidate.issubset(
            candidate.keys()
        ):
            return None, 400

        name = candidate["name"]

        if not valid_nonempty_string(name):
            return None, 400

        if name in seen_names:
            return None, 400

        seen_names.add(name)

        unsupported_reason = candidate.get(
            "unsupportedReason",
            None
        )

        if (
            unsupported_reason is not None
            and not isinstance(
                unsupported_reason,
                str
            )
        ):
            return None, 400

        inventory, total_bytes, package_digest, files_valid = (
            build_inventory(
                candidate["files"]
            )
        )

        # Invalid files => empty inventory/null totals.
        if not files_valid:
            output.append({
                "name": name,
                "status": "invalid",
                "inventory": [],
                "totalBytes": None,
                "packageDigest": None,
                "reasonCodes": ["INVALID_INPUT"]
            })
            continue

        # ----------------------------------------------------
        # Allowed unsupported reason
        # ----------------------------------------------------

        if unsupported_reason is not None:

            if unsupported_reason in allowed:
                output.append({
                    "name": name,
                    "status": "unsupported",
                    "inventory": inventory,
                    "totalBytes": total_bytes,
                    "packageDigest": package_digest,
                    "reasonCodes": []
                })
                continue

        codes = []

        # ----------------------------------------------------
        # Unsupported reason not allowed
        # ----------------------------------------------------

        if unsupported_reason is not None:
            if unsupported_reason not in allowed:
                codes.append(
                    "UNALLOWED_UNSUPPORTED_REASON"
                )

        # ----------------------------------------------------
        # Loadable
        # ----------------------------------------------------

        if not isinstance(
            candidate["loadable"],
            bool
        ):
            codes.append("INVALID_INPUT")

        elif candidate["loadable"] is not True:
            codes.append("NOT_LOADABLE")

        # ----------------------------------------------------
        # Calibration
        # ----------------------------------------------------

        if candidate["calibrationDigest"] != calibration_digest:
            codes.append(
                "CALIBRATION_MISMATCH"
            )

        # ----------------------------------------------------
        # Tokenizer
        # ----------------------------------------------------

        if candidate["tokenizerDigest"] != tokenizer_digest:
            codes.append(
                "TOKENIZER_MISMATCH"
            )

        codes = unique_sorted(codes)

        if codes:
            status = "invalid"
        else:
            status = "frozen"

        output.append({
            "name": name,
            "status": status,
            "inventory": inventory,
            "totalBytes": total_bytes,
            "packageDigest": package_digest,
            "reasonCodes": codes
        })

    output.sort(
        key=lambda x: utf8_key(x["name"])
    )

    response = {
        "freezeId": freeze_id,
        "candidates": output
    }

    return response, 200


# ============================================================
# SELECT
# ============================================================

def perform_select(payload):

    required = {
        "phase",
        "freezeId",
        "candidates",
        "policy",
        "latencies",
        "rows"
    }

    # Missing required top-level fields is HTTP 400.
    if not required.issubset(payload.keys()):
        return None, 400

    if payload["phase"] != "select":
        return None, 400

    freeze_id = payload["freezeId"]

    if not valid_nonempty_string(
        freeze_id,
        128
    ):
        return None, 400

    candidates = payload["candidates"]
    policy = payload["policy"]
    latencies = payload["latencies"]
    rows = payload["rows"]

    # Explicit malformed types => HTTP 400.
    if not isinstance(candidates, list):
        return None, 400

    if not isinstance(policy, dict):
        return None, 400

    if not isinstance(rows, list):
        return None, 400

    if not isinstance(latencies, dict):
        return None, 400

    # IMPORTANT:
    # Empty arrays are not themselves a top-level 400 condition.

    # --------------------------------------------------------
    # Freeze lookup
    # --------------------------------------------------------

    stored = FREEZES.get(freeze_id)

    if stored is None:
        return {
            "freezeId": freeze_id,
            "selected": None,
            "results": [],
            "packageManifest": None
        }, 200

    stored_candidates = stored[
        "response"
    ]["candidates"]

    # Supplied candidate array must exactly match frozen response.
    if candidates != stored_candidates:
        return {
            "freezeId": freeze_id,
            "selected": None,
            "results": [],
            "packageManifest": None
        }, 200

    # --------------------------------------------------------
    # Policy
    # --------------------------------------------------------

    policy_required = {
        "maxBytes",
        "aggregateFloor",
        "requiredSlices",
        "maxLatencyMs",
        "candidateOrder"
    }

    if not policy_required.issubset(
        policy.keys()
    ):
        return {
            "freezeId": freeze_id,
            "selected": None,
            "results": [],
            "packageManifest": None
        }, 200

    max_bytes = policy["maxBytes"]
    aggregate_floor = policy[
        "aggregateFloor"
    ]
    required_slices = policy[
        "requiredSlices"
    ]
    max_latency = policy[
        "maxLatencyMs"
    ]
    candidate_order = policy[
        "candidateOrder"
    ]

    if not safe_int(max_bytes):
        return {
            "freezeId": freeze_id,
            "selected": None,
            "results": [],
            "packageManifest": None
        }, 200

    if not in_range_01(aggregate_floor):
        return {
            "freezeId": freeze_id,
            "selected": None,
            "results": [],
            "packageManifest": None
        }, 200

    if not isinstance(
        required_slices,
        dict
    ):
        return {
            "freezeId": freeze_id,
            "selected": None,
            "results": [],
            "packageManifest": None
        }, 200

    for name, floor in required_slices.items():

        if not isinstance(name, str) or name == "":
            return {
                "freezeId": freeze_id,
                "selected": None,
                "results": [],
                "packageManifest": None
            }, 200

        if not in_range_01(floor):
            return {
                "freezeId": freeze_id,
                "selected": None,
                "results": [],
                "packageManifest": None
            }, 200

    if not nonnegative_finite(
        max_latency
    ):
        return {
            "freezeId": freeze_id,
            "selected": None,
            "results": [],
            "packageManifest": None
        }, 200

    if not isinstance(
        candidate_order,
        list
    ):
        return {
            "freezeId": freeze_id,
            "selected": None,
            "results": [],
            "packageManifest": None
        }, 200

    if any(
        not isinstance(x, str) or x == ""
        for x in candidate_order
    ):
        return {
            "freezeId": freeze_id,
            "selected": None,
            "results": [],
            "packageManifest": None
        }, 200

    if len(set(candidate_order)) != len(
        candidate_order
    ):
        return {
            "freezeId": freeze_id,
            "selected": None,
            "results": [],
            "packageManifest": None
        }, 200

    frozen_names = {
        item["name"]
        for item in stored_candidates
    }

    if set(candidate_order) != frozen_names:
        return {
            "freezeId": freeze_id,
            "selected": None,
            "results": [],
            "packageManifest": None
        }, 200

    # --------------------------------------------------------
    # Validate rows
    # --------------------------------------------------------

    rows_valid = True

    for row in rows:

        if not isinstance(row, dict):
            rows_valid = False
            break

        required_row = {
            "label",
            "slice",
            "predictions"
        }

        if not required_row.issubset(
            row.keys()
        ):
            rows_valid = False
            break

        label = row["label"]
        slice_name = row["slice"]
        predictions = row["predictions"]

        if (
            not isinstance(label, int)
            or isinstance(label, bool)
            or label not in (0, 1)
        ):
            rows_valid = False
            break

        if (
            not isinstance(slice_name, str)
            or slice_name == ""
        ):
            rows_valid = False
            break

        if not isinstance(
            predictions,
            dict
        ):
            rows_valid = False
            break

    # --------------------------------------------------------
    # Evaluate candidates
    # --------------------------------------------------------

    results = []

    for candidate in stored_candidates:

        name = candidate["name"]
        codes = []

        status = candidate["status"]

        if status != "frozen":
            codes.append("NOT_FROZEN")

        # ----------------------------------------------------
        # Manifest validation
        # ----------------------------------------------------

        manifest_ok = True

        inventory = candidate["inventory"]

        if status == "invalid":
            manifest_ok = False

        valid_inventory, recomputed_total, recomputed_digest = (
            validate_inventory(
                inventory
            )
        )

        if not valid_inventory:
            manifest_ok = False
        else:
            if (
                recomputed_total
                != candidate["totalBytes"]
            ):
                manifest_ok = False

            if (
                recomputed_digest
                != candidate["packageDigest"]
            ):
                manifest_ok = False

        if not manifest_ok:
            codes.append(
                "INVALID_MANIFEST"
            )

        aggregate = None
        slice_values = {}
        total_bytes = None
        latency_value = None

        # ----------------------------------------------------
        # Predictions
        # ----------------------------------------------------

        if not rows_valid:

            codes.append(
                "INVALID_PREDICTIONS"
            )

        else:

            correct = 0
            slice_stats = {}
            prediction_ok = True

            for row in rows:

                predictions = row[
                    "predictions"
                ]

                if name not in predictions:
                    prediction_ok = False
                    break

                prediction = predictions[
                    name
                ]

                if (
                    not isinstance(
                        prediction,
                        int
                    )
                    or isinstance(
                        prediction,
                        bool
                    )
                    or prediction not in (0, 1)
                ):
                    prediction_ok = False
                    break

                label = row["label"]
                slice_name = row["slice"]

                if prediction == label:
                    correct += 1

                if slice_name not in slice_stats:
                    slice_stats[
                        slice_name
                    ] = [0, 0]

                slice_stats[
                    slice_name
                ][1] += 1

                if prediction == label:
                    slice_stats[
                        slice_name
                    ][0] += 1

            if not prediction_ok:

                codes.append(
                    "INVALID_PREDICTIONS"
                )

            elif len(rows) == 0:

                aggregate = None

            else:

                aggregate = round(
                    correct / len(rows),
                    12
                )

                if aggregate < float(
                    aggregate_floor
                ):
                    codes.append(
                        "AGGREGATE_FLOOR"
                    )

                for slice_name in sorted(
                    slice_stats.keys(),
                    key=utf8_key
                ):

                    good, total = slice_stats[
                        slice_name
                    ]

                    slice_values[
                        slice_name
                    ] = round(
                        good / total,
                        12
                    )

                for slice_name in sorted(
                    required_slices.keys(),
                    key=utf8_key
                ):

                    if slice_name not in slice_values:
                        codes.append(
                            f"MISSING_SLICE:{slice_name}"
                        )
                    elif (
                        slice_values[slice_name]
                        < float(
                            required_slices[
                                slice_name
                            ]
                        )
                    ):
                        codes.append(
                            f"SLICE_FLOOR:{slice_name}"
                        )

        # ----------------------------------------------------
        # Size
        # ----------------------------------------------------

        if safe_int(
            candidate["totalBytes"]
        ):
            total_bytes = candidate[
                "totalBytes"
            ]

            if total_bytes > max_bytes:
                codes.append(
                    "SIZE_LIMIT"
                )

        # ----------------------------------------------------
        # Latency
        # ----------------------------------------------------

        if name in latencies:

            latency = latencies[name]

            if nonnegative_finite(
                latency
            ):
                latency_value = latency

                if float(latency) > float(
                    max_latency
                ):
                    codes.append(
                        "LATENCY_LIMIT"
                    )

        # ----------------------------------------------------
        # Admission
        # ----------------------------------------------------

        codes = unique_sorted(codes)

        admitted = (
            status == "frozen"
            and manifest_ok
            and rows_valid
            and aggregate is not None
            and total_bytes is not None
            and latency_value is not None
            and len(codes) == 0
        )

        results.append({
            "name": name,
            "aggregate": aggregate,
            "slices": slice_values,
            "totalBytes": total_bytes,
            "latencyMs": latency_value,
            "admitted": admitted,
            "reasonCodes": codes
        })

    # --------------------------------------------------------
    # Result ordering
    # --------------------------------------------------------

    order_index = {
        name: i
        for i, name in enumerate(
            candidate_order
        )
    }

    results.sort(
        key=lambda result: (
            order_index.get(
                result["name"],
                len(candidate_order)
            ),
            utf8_key(result["name"])
        )
    )

    # --------------------------------------------------------
    # Winner
    # --------------------------------------------------------

    admitted = [
        result
        for result in results
        if result["admitted"]
    ]

    if admitted:

        winner = sorted(
            admitted,
            key=lambda result: (
                result["totalBytes"],
                float(result["latencyMs"]),
                order_index[
                    result["name"]
                ]
            )
        )[0]

        selected = winner["name"]
        package_manifest = winner

    else:
        selected = None
        package_manifest = None

    return {
        "freezeId": freeze_id,
        "selected": selected,
        "results": results,
        "packageManifest": package_manifest
    }, 200


# ============================================================
# MISSING HELPER
# ============================================================

def in_range_01(value):
    return (
        finite(value)
        and 0 <= float(value) <= 1
    )


# ============================================================
# ROUTES
# ============================================================

@app.get("/")
def health():
    return {"status": "ok"}


@app.post("/quantize")
async def quantize(payload: dict):

    if not isinstance(payload, dict):
        return JSONResponse(
            status_code=400,
            content={
                "error": "INVALID_INPUT"
            }
        )

    phase = payload.get("phase")

    # ========================================================
    # FREEZE
    # ========================================================

    if phase == "freeze":

        freeze_id = payload.get(
            "freezeId"
        )

        if (
            isinstance(freeze_id, str)
            and freeze_id in FREEZES
        ):

            incoming_fp = fingerprint(
                payload
            )

            if (
                incoming_fp
                != FREEZES[
                    freeze_id
                ]["fingerprint"]
            ):
                return JSONResponse(
                    status_code=409,
                    content={
                        "error":
                        "FREEZE_ID_CONFLICT"
                    }
                )

            return FREEZES[
                freeze_id
            ]["response"]

        result, status = perform_freeze(
            payload
        )

        if result is None:
            return JSONResponse(
                status_code=400,
                content={
                    "error":
                    "INVALID_INPUT"
                }
            )

        # Only successful parsing reserves freezeId.
        FREEZES[freeze_id] = {
            "fingerprint":
                fingerprint(payload),
            "response": result
        }

        return JSONResponse(
            status_code=status,
            content=result
        )

    # ========================================================
    # SELECT
    # ========================================================

    if phase == "select":

        result, status = perform_select(
            payload
        )

        if result is None:
            return JSONResponse(
                status_code=400,
                content={
                    "error":
                    "INVALID_INPUT"
                }
            )

        return JSONResponse(
            status_code=status,
            content=result
        )

    # ========================================================
    # UNKNOWN / MISSING PHASE
    # ========================================================

    return JSONResponse(
        status_code=400,
        content={
            "error": "INVALID_INPUT"
        }
    )
