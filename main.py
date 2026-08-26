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
    return sorted(set(codes), key=utf8_key)


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


def unit_interval(value):
    return (
        finite(value)
        and 0 <= float(value) <= 1
    )


def nonempty_string(value, max_len=None):
    if not isinstance(value, str) or value == "":
        return False

    if max_len is not None and len(value) > max_len:
        return False

    return True


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def request_fingerprint(payload):
    return sha256_bytes(
        compact_json(payload).encode("utf-8")
    )


def empty_select_response(freeze_id):
    return {
        "freezeId": freeze_id,
        "selected": None,
        "results": [],
        "packageManifest": None
    }


# ============================================================
# INVENTORY
# ============================================================

def make_inventory(files):
    """
    Returns:
        inventory, total_bytes, package_digest, valid
    """

    if not isinstance(files, dict) or len(files) == 0:
        return [], None, None, False

    inventory = []
    seen_names = set()

    for filename, content in files.items():

        if not isinstance(filename, str) or filename == "":
            return [], None, None, False

        if filename in seen_names:
            return [], None, None, False

        seen_names.add(filename)

        if not isinstance(content, str):
            return [], None, None, False

        raw = content.encode("utf-8")

        inventory.append({
            "name": filename,
            "bytes": len(raw),
            "sha256": sha256_bytes(raw)
        })

    inventory.sort(
        key=lambda item: utf8_key(item["name"])
    )

    total_bytes = sum(
        item["bytes"]
        for item in inventory
    )

    package_digest = sha256_bytes(
        compact_json(inventory).encode("utf-8")
    )

    return (
        inventory,
        total_bytes,
        package_digest,
        True
    )


def validate_recorded_inventory(
    inventory,
    total_bytes,
    package_digest
):
    """
    Recompute the inventory total and package digest from
    the recorded inventory.
    """

    if not isinstance(inventory, list):
        return False, None, None

    if len(inventory) == 0:
        return False, None, None

    rebuilt = []
    seen_names = set()
    computed_total = 0

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
        size = item["bytes"]
        digest = item["sha256"]

        if not isinstance(name, str) or name == "":
            return False, None, None

        if name in seen_names:
            return False, None, None

        seen_names.add(name)

        if not safe_int(size):
            return False, None, None

        if (
            not isinstance(digest, str)
            or SHA256_RE.fullmatch(digest) is None
        ):
            return False, None, None

        computed_total += size

        rebuilt.append({
            "name": name,
            "bytes": size,
            "sha256": digest
        })

    rebuilt.sort(
        key=lambda item: utf8_key(item["name"])
    )

    computed_digest = sha256_bytes(
        compact_json(rebuilt).encode("utf-8")
    )

    valid = (
        computed_total == total_bytes
        and computed_digest == package_digest
    )

    return (
        valid,
        computed_total,
        computed_digest
    )


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

    # These are request-structure failures.
    if not required.issubset(payload.keys()):
        return None, 400

    if payload["phase"] != "freeze":
        return None, 400

    freeze_id = payload["freezeId"]

    if not nonempty_string(freeze_id, 128):
        return None, 400

    calibration_digest = payload[
        "calibrationDigest"
    ]

    tokenizer_digest = payload[
        "tokenizerDigest"
    ]

    if not nonempty_string(calibration_digest):
        return None, 400

    if not nonempty_string(tokenizer_digest):
        return None, 400

    allowed_reasons = payload[
        "allowedUnsupportedReasons"
    ]

    if not isinstance(allowed_reasons, list):
        return None, 400

    # Names/reasons must be unique non-empty strings.
    if any(
        not nonempty_string(reason)
        for reason in allowed_reasons
    ):
        return None, 400

    if len(set(allowed_reasons)) != len(
        allowed_reasons
    ):
        return None, 400

    candidates = payload["candidates"]

    # Explicitly a 400 condition for empty/non-array
    # freeze candidate list.
    if not isinstance(candidates, list):
        return None, 400

    if len(candidates) == 0:
        return None, 400

    output = []
    seen_names = set()

    for candidate in candidates:

        # Candidate-specific malformed data belongs in
        # candidate result, not HTTP 400.
        if not isinstance(candidate, dict):

            output.append({
                "name": "",
                "status": "invalid",
                "inventory": [],
                "totalBytes": None,
                "packageDigest": None,
                "reasonCodes": [
                    "INVALID_INPUT"
                ]
            })

            continue

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

            name = candidate.get("name")

            if not isinstance(name, str):
                name = ""

            output.append({
                "name": name,
                "status": "invalid",
                "inventory": [],
                "totalBytes": None,
                "packageDigest": None,
                "reasonCodes": [
                    "INVALID_INPUT"
                ]
            })

            continue

        name = candidate["name"]

        if not nonempty_string(name):

            output.append({
                "name": name
                if isinstance(name, str)
                else "",
                "status": "invalid",
                "inventory": [],
                "totalBytes": None,
                "packageDigest": None,
                "reasonCodes": [
                    "INVALID_INPUT"
                ]
            })

            continue

        if name in seen_names:

            output.append({
                "name": name,
                "status": "invalid",
                "inventory": [],
                "totalBytes": None,
                "packageDigest": None,
                "reasonCodes": [
                    "INVALID_INPUT"
                ]
            })

            continue

        seen_names.add(name)

        # ----------------------------------------------------
        # Files
        # ----------------------------------------------------

        inventory, total_bytes, package_digest, files_valid = (
            make_inventory(candidate["files"])
        )

        if not files_valid:

            output.append({
                "name": name,
                "status": "invalid",
                "inventory": [],
                "totalBytes": None,
                "packageDigest": None,
                "reasonCodes": [
                    "INVALID_INPUT"
                ]
            })

            continue

        codes = []

        unsupported_reason = candidate.get(
            "unsupportedReason",
            None
        )

        # ----------------------------------------------------
        # unsupportedReason
        # ----------------------------------------------------

        if unsupported_reason is not None:

            if not isinstance(
                unsupported_reason,
                str
            ) or unsupported_reason == "":

                codes.append("INVALID_INPUT")

            elif unsupported_reason in allowed_reasons:

                # Allowed unsupported reason means the
                # candidate is explicitly unsupported.
                output.append({
                    "name": name,
                    "status": "unsupported",
                    "inventory": inventory,
                    "totalBytes": total_bytes,
                    "packageDigest": package_digest,
                    "reasonCodes": []
                })

                continue

            else:
                codes.append(
                    "UNALLOWED_UNSUPPORTED_REASON"
                )

        # ----------------------------------------------------
        # loadable
        # ----------------------------------------------------

        if not isinstance(
            candidate["loadable"],
            bool
        ):
            codes.append("INVALID_INPUT")

        elif candidate["loadable"] is not True:
            codes.append("NOT_LOADABLE")

        # ----------------------------------------------------
        # calibration
        # ----------------------------------------------------

        if (
            candidate["calibrationDigest"]
            != calibration_digest
        ):
            codes.append(
                "CALIBRATION_MISMATCH"
            )

        # ----------------------------------------------------
        # tokenizer
        # ----------------------------------------------------

        if (
            candidate["tokenizerDigest"]
            != tokenizer_digest
        ):
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

    # --------------------------------------------------------
    # Sort output by UTF-8 candidate name
    # --------------------------------------------------------

    output.sort(
        key=lambda item: utf8_key(
            item["name"]
        )
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

    # These are the top-level structural requirements.
    if not required.issubset(payload.keys()):
        return None, 400

    if payload["phase"] != "select":
        return None, 400

    freeze_id = payload["freezeId"]

    if not nonempty_string(freeze_id, 128):
        return None, 400

    candidates = payload["candidates"]
    policy = payload["policy"]
    latencies = payload["latencies"]
    rows = payload["rows"]

    # These are explicitly mentioned as HTTP-400 input errors.
    if not isinstance(candidates, list):
        return None, 400

    if not isinstance(rows, list):
        return None, 400

    if not isinstance(policy, dict):
        return None, 400

    if not isinstance(latencies, dict):
        # Treat malformed latency object as invalid input.
        return None, 400

    # --------------------------------------------------------
    # Freeze lineage
    # --------------------------------------------------------

    stored = FREEZES.get(freeze_id)

    if stored is None:
        return empty_select_response(
            freeze_id
        ), 200

    stored_candidates = stored[
        "response"
    ]["candidates"]

    # Candidate array must exactly equal stored freeze response.
    if candidates != stored_candidates:
        return empty_select_response(
            freeze_id
        ), 200

    # --------------------------------------------------------
    # Policy validation
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
        return empty_select_response(
            freeze_id
        ), 200

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

    policy_valid = True

    if not safe_int(max_bytes):
        policy_valid = False

    if not unit_interval(
        aggregate_floor
    ):
        policy_valid = False

    if not isinstance(
        required_slices,
        dict
    ):
        policy_valid = False

    if isinstance(required_slices, dict):
        for slice_name, floor in (
            required_slices.items()
        ):

            if (
                not isinstance(
                    slice_name,
                    str
                )
                or slice_name == ""
                or not unit_interval(floor)
            ):
                policy_valid = False

    if not nonnegative_finite(
        max_latency
    ):
        policy_valid = False

    if not isinstance(
        candidate_order,
        list
    ):
        policy_valid = False
    else:

        if len(candidate_order) == 0:
            policy_valid = False

        if any(
            not isinstance(x, str)
            or x == ""
            for x in candidate_order
        ):
            policy_valid = False

        if len(set(candidate_order)) != len(
            candidate_order
        ):
            policy_valid = False

    frozen_names = {
        candidate["name"]
        for candidate in stored_candidates
    }

    if (
        isinstance(candidate_order, list)
        and set(candidate_order) != frozen_names
    ):
        policy_valid = False

    # --------------------------------------------------------
    # Invalid policy => normal JSON response.
    # --------------------------------------------------------

    if not policy_valid:

        results = []

        for candidate in stored_candidates:

            results.append({
                "name": candidate["name"],
                "aggregate": None,
                "slices": {},
                "totalBytes": (
                    candidate["totalBytes"]
                    if isinstance(
                        candidate["totalBytes"],
                        int
                    )
                    else None
                ),
                "latencyMs": (
                    latencies.get(
                        candidate["name"]
                    )
                    if candidate["name"] in latencies
                    else None
                ),
                "admitted": False,
                "reasonCodes": [
                    "INVALID_POLICY"
                ]
            })

        return {
            "freezeId": freeze_id,
            "selected": None,
            "results": results,
            "packageManifest": None
        }, 200

    # --------------------------------------------------------
    # Row structure
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
    # Evaluate each candidate
    # --------------------------------------------------------

    results = []

    for candidate in stored_candidates:

        name = candidate["name"]

        codes = []

        # ----------------------------------------------------
        # Frozen state
        # ----------------------------------------------------

        if candidate["status"] != "frozen":
            codes.append("NOT_FROZEN")

        # ----------------------------------------------------
        # Manifest
        # ----------------------------------------------------

        manifest_valid = False

        if candidate["status"] == "frozen":

            manifest_valid, _, _ = (
                validate_recorded_inventory(
                    candidate["inventory"],
                    candidate["totalBytes"],
                    candidate["packageDigest"]
                )
            )

        if not manifest_valid:
            codes.append(
                "INVALID_MANIFEST"
            )

        # ----------------------------------------------------
        # Prediction metrics
        # ----------------------------------------------------

        aggregate = None
        slice_values = {}

        if not rows_valid:

            codes.append(
                "INVALID_PREDICTIONS"
            )

        elif len(rows) == 0:

            # Empty rows => null aggregate/slices.
            aggregate = None

        else:

            prediction_valid = True
            correct = 0
            slice_stats = {}

            for row in rows:

                predictions = row[
                    "predictions"
                ]

                if name not in predictions:
                    prediction_valid = False
                    break

                prediction = predictions[name]

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
                    prediction_valid = False
                    break

                label = row["label"]
                slice_name = row["slice"]

                if prediction == label:
                    correct += 1

                if slice_name not in slice_stats:
                    slice_stats[slice_name] = [
                        0,
                        0
                    ]

                slice_stats[slice_name][1] += 1

                if prediction == label:
                    slice_stats[slice_name][0] += 1

            if not prediction_valid:

                codes.append(
                    "INVALID_PREDICTIONS"
                )

            else:

                aggregate = round(
                    correct / len(rows),
                    12
                )

                if (
                    aggregate
                    < float(aggregate_floor)
                ):
                    codes.append(
                        "AGGREGATE_FLOOR"
                    )

                for slice_name in sorted(
                    slice_stats.keys(),
                    key=utf8_key
                ):

                    correct_slice, count_slice = (
                        slice_stats[slice_name]
                    )

                    slice_values[slice_name] = round(
                        correct_slice / count_slice,
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

        total_bytes = None

        if safe_int(
            candidate["totalBytes"]
        ):

            total_bytes = candidate[
                "totalBytes"
            ]

            if (
                total_bytes
                > max_bytes
            ):
                codes.append(
                    "SIZE_LIMIT"
                )

        # ----------------------------------------------------
        # Latency
        # ----------------------------------------------------

        latency_value = None

        if name in latencies:

            latency = latencies[name]

            if nonnegative_finite(
                latency
            ):

                latency_value = latency

                if (
                    float(latency)
                    > float(max_latency)
                ):
                    codes.append(
                        "LATENCY_LIMIT"
                    )

        # ----------------------------------------------------
        # Final candidate admission
        # ----------------------------------------------------

        codes = unique_sorted(codes)

        admitted = (
            candidate["status"] == "frozen"
            and manifest_valid
            and rows_valid
            and len(rows) > 0
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
    # Results ordered by candidateOrder.
    # --------------------------------------------------------

    order_position = {
        name: index
        for index, name in enumerate(
            candidate_order
        )
    }

    results.sort(
        key=lambda result: (
            order_position.get(
                result["name"],
                len(candidate_order)
            ),
            utf8_key(result["name"])
        )
    )

    # --------------------------------------------------------
    # Winner:
    # smaller bytes
    # lower latency
    # candidate order
    # --------------------------------------------------------

    admitted = [
        result
        for result in results
        if result["admitted"]
    ]

    if len(admitted) == 0:

        selected = None
        package_manifest = None

    else:

        winner = sorted(
            admitted,
            key=lambda result: (
                result["totalBytes"],
                float(result["latencyMs"]),
                order_position[
                    result["name"]
                ]
            )
        )[0]

        selected = winner["name"]
        package_manifest = winner

    return {
        "freezeId": freeze_id,
        "selected": selected,
        "results": results,
        "packageManifest": package_manifest
    }, 200


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

    if phase == "freeze":

        freeze_id = payload.get(
            "freezeId"
        )

        # ----------------------------------------------------
        # Replay / conflict
        # ----------------------------------------------------

        if (
            isinstance(freeze_id, str)
            and freeze_id in FREEZES
        ):

            incoming_fp = request_fingerprint(
                payload
            )

            stored = FREEZES[freeze_id]

            if (
                incoming_fp
                != stored["fingerprint"]
            ):

                return JSONResponse(
                    status_code=409,
                    content={
                        "error":
                        "FREEZE_ID_CONFLICT"
                    }
                )

            return stored["response"]

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

        # Persist only after successful freeze request
        # parsing.
        FREEZES[freeze_id] = {
            "fingerprint":
                request_fingerprint(
                    payload
                ),
            "response": result
        }

        return JSONResponse(
            status_code=status,
            content=result
        )

    elif phase == "select":

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

    else:

        return JSONResponse(
            status_code=400,
            content={
                "error":
                "INVALID_INPUT"
            }
        )
