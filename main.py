from fastapi import FastAPI
from fastapi.responses import JSONResponse

import hashlib
import json
import math


app = FastAPI()

SAFE_INT_MAX = 9007199254740991

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


def positive_safe_int(value):
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and 0 < value <= SAFE_INT_MAX
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


def sha256_text(value):
    return hashlib.sha256(
        value.encode("utf-8")
    ).hexdigest()


def freeze_fingerprint(payload):
    return hashlib.sha256(
        compact_json(payload).encode("utf-8")
    ).hexdigest()


def invalid_freeze_result(freeze_id, candidates=None):
    return {
        "freezeId": (
            freeze_id
            if isinstance(freeze_id, str)
            else ""
        ),
        "candidates": (
            candidates
            if candidates is not None
            else []
        ),
    }


# ============================================================
# FILE INVENTORY
# ============================================================

def build_inventory(files):
    """
    Returns:
        inventory, total_bytes, package_digest, valid
    """

    if not isinstance(files, dict):
        return [], None, None, False

    if len(files) == 0:
        return [], None, None, False

    seen = set()
    raw_items = []

    for filename, content in files.items():

        if not isinstance(filename, str):
            return [], None, None, False

        if filename == "":
            return [], None, None, False

        if not isinstance(content, str):
            return [], None, None, False

        if filename in seen:
            return [], None, None, False

        seen.add(filename)

        encoded = content.encode("utf-8")

        raw_items.append(
            {
                "name": filename,
                "bytes": len(encoded),
                "sha256": hashlib.sha256(
                    encoded
                ).hexdigest(),
            }
        )

    raw_items.sort(
        key=lambda x: utf8_key(x["name"])
    )

    total_bytes = sum(
        item["bytes"]
        for item in raw_items
    )

    # Exact inventory structure and key order.
    inventory_json = compact_json(
        raw_items
    )

    package_digest = hashlib.sha256(
        inventory_json.encode("utf-8")
    ).hexdigest()

    return (
        raw_items,
        total_bytes,
        package_digest,
        True
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
        "candidates",
    }

    if not required.issubset(
        payload.keys()
    ):
        return None, 400

    if payload["phase"] != "freeze":
        return None, 400

    freeze_id = payload["freezeId"]

    if not valid_nonempty_string(
        freeze_id,
        128
    ):
        return None, 400

    calibration_digest = payload[
        "calibrationDigest"
    ]

    tokenizer_digest = payload[
        "tokenizerDigest"
    ]

    if not valid_nonempty_string(
        calibration_digest
    ):
        return None, 400

    if not valid_nonempty_string(
        tokenizer_digest
    ):
        return None, 400

    allowed_reasons = payload[
        "allowedUnsupportedReasons"
    ]

    if not isinstance(
        allowed_reasons,
        list
    ):
        return None, 400

    if len(set(allowed_reasons)) != len(
        allowed_reasons
    ):
        return None, 400

    if any(
        not valid_nonempty_string(x)
        for x in allowed_reasons
    ):
        return None, 400

    candidates = payload[
        "candidates"
    ]

    if not isinstance(
        candidates,
        list
    ):
        return None, 400

    # Assignment says empty/non-array freeze candidates
    # is HTTP 400 INVALID_INPUT.
    if len(candidates) == 0:
        return None, 400

    seen_names = set()
    output = []

    for candidate in candidates:

        if not isinstance(
            candidate,
            dict
        ):
            return None, 400

        required_candidate = {
            "name",
            "files",
            "loadable",
            "calibrationDigest",
            "tokenizerDigest",
        }

        if not required_candidate.issubset(
            candidate.keys()
        ):
            return None, 400

        name = candidate["name"]

        if not valid_nonempty_string(
            name
        ):
            return None, 400

        if name in seen_names:
            return None, 400

        seen_names.add(name)

        # unsupportedReason is optional.
        if "unsupportedReason" in candidate:
            unsupported_reason = candidate[
                "unsupportedReason"
            ]
            if (
                unsupported_reason is not None
                and not isinstance(
                    unsupported_reason,
                    str
                )
            ):
                return None, 400
        else:
            unsupported_reason = None

        files = candidate["files"]

        inventory, total_bytes, package_digest, files_valid = (
            build_inventory(files)
        )

        # Invalid files => empty inventory/null values.
        if not files_valid:

            output.append(
                {
                    "name": name,
                    "status": "invalid",
                    "inventory": [],
                    "totalBytes": None,
                    "packageDigest": None,
                    "reasonCodes": [
                        "INVALID_INPUT"
                    ],
                }
            )

            continue

        codes = []

        # ----------------------------------------------------
        # Unsupported reason
        # ----------------------------------------------------

        if unsupported_reason is not None:

            if unsupported_reason in allowed_reasons:

                output.append(
                    {
                        "name": name,
                        "status": "unsupported",
                        "inventory": inventory,
                        "totalBytes": total_bytes,
                        "packageDigest": package_digest,
                        "reasonCodes": [],
                    }
                )

                continue

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
            codes.append(
                "INVALID_INPUT"
            )

        elif candidate["loadable"] is not True:
            codes.append(
                "NOT_LOADABLE"
            )

        # ----------------------------------------------------
        # Calibration
        # ----------------------------------------------------

        if (
            candidate["calibrationDigest"]
            != calibration_digest
        ):
            codes.append(
                "CALIBRATION_MISMATCH"
            )

        # ----------------------------------------------------
        # Tokenizer
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

            output.append(
                {
                    "name": name,
                    "status": "invalid",
                    "inventory": inventory,
                    "totalBytes": total_bytes,
                    "packageDigest": package_digest,
                    "reasonCodes": codes,
                }
            )

        else:

            output.append(
                {
                    "name": name,
                    "status": "frozen",
                    "inventory": inventory,
                    "totalBytes": total_bytes,
                    "packageDigest": package_digest,
                    "reasonCodes": [],
                }
            )

    output.sort(
        key=lambda x: utf8_key(x["name"])
    )

    response = {
        "freezeId": freeze_id,
        "candidates": output,
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
        "rows",
    }

    if not required.issubset(
        payload.keys()
    ):
        return None, 400

    if payload["phase"] != "select":
        return None, 400

    freeze_id = payload[
        "freezeId"
    ]

    if not valid_nonempty_string(
        freeze_id,
        128
    ):
        return None, 400

    candidates = payload[
        "candidates"
    ]

    policy = payload[
        "policy"
    ]

    latencies = payload[
        "latencies"
    ]

    rows = payload[
        "rows"
    ]

    if not isinstance(
        candidates,
        list
    ):
        return None, 400

    if not isinstance(
        policy,
        dict
    ):
        return None, 400

    if not isinstance(
        latencies,
        dict
    ):
        return None, 400

    if not isinstance(
        rows,
        list
    ):
        return None, 400

    if len(candidates) == 0:
        return None, 400

    if len(rows) == 0:
        return None, 400

    # --------------------------------------------------------
    # Freeze lineage
    # --------------------------------------------------------

    stored = FREEZES.get(
        freeze_id
    )

    if stored is None:
        return {
            "freezeId": freeze_id,
            "selected": None,
            "results": [],
            "packageManifest": None,
        }, 200

    stored_candidates = stored[
        "response"
    ]["candidates"]

    # Candidate array must exactly equal frozen response.
    if candidates != stored_candidates:

        return {
            "freezeId": freeze_id,
            "selected": None,
            "results": [],
            "packageManifest": None,
        }, 200

    # --------------------------------------------------------
    # Policy
    # --------------------------------------------------------

    policy_required = {
        "maxBytes",
        "aggregateFloor",
        "requiredSlices",
        "maxLatencyMs",
        "candidateOrder",
    }

    if not policy_required.issubset(
        policy.keys()
    ):
        return None, 400

    if not safe_int(
        policy["maxBytes"]
    ):
        return {
            "freezeId": freeze_id,
            "selected": None,
            "results": [],
            "packageManifest": None,
        }, 200

    if not finite(
        policy["aggregateFloor"]
    ):
        return None, 400

    if not 0 <= float(
        policy["aggregateFloor"]
    ) <= 1:
        return None, 400

    required_slices = policy[
        "requiredSlices"
    ]

    if not isinstance(
        required_slices,
        dict
    ):
        return None, 400

    for slice_name, floor in (
        required_slices.items()
    ):

        if (
            not isinstance(
                slice_name,
                str
            )
            or slice_name == ""
        ):
            return None, 400

        if not finite(floor):
            return None, 400

        if not 0 <= float(floor) <= 1:
            return None, 400

    if not nonnegative_finite(
        policy["maxLatencyMs"]
    ):
        return None, 400

    candidate_order = policy[
        "candidateOrder"
    ]

    if not isinstance(
        candidate_order,
        list
    ):
        return None, 400

    if len(candidate_order) == 0:
        return None, 400

    if any(
        not isinstance(x, str)
        or x == ""
        for x in candidate_order
    ):
        return None, 400

    if len(set(candidate_order)) != len(
        candidate_order
    ):
        return None, 400

    frozen_names = {
        c["name"]
        for c in stored_candidates
    }

    if set(candidate_order) != frozen_names:
        return {
            "freezeId": freeze_id,
            "selected": None,
            "results": [],
            "packageManifest": None,
        }, 200

    # --------------------------------------------------------
    # Latencies
    # --------------------------------------------------------

    for name in frozen_names:

        if name not in latencies:
            continue

        if not nonnegative_finite(
            latencies[name]
        ):
            # Value cannot be validated.
            continue

    # --------------------------------------------------------
    # Rows
    # --------------------------------------------------------

    valid_rows = True

    for row in rows:

        if not isinstance(
            row,
            dict
        ):
            valid_rows = False
            break

        if not {
            "label",
            "slice",
            "predictions"
        }.issubset(row.keys()):
            valid_rows = False
            break

        label = row["label"]
        slice_name = row["slice"]
        predictions = row[
            "predictions"
        ]

        if (
            not isinstance(
                label,
                int
            )
            or isinstance(
                label,
                bool
            )
            or label not in (0, 1)
        ):
            valid_rows = False
            break

        if not isinstance(
            slice_name,
            str
        ) or slice_name == "":
            valid_rows = False
            break

        if not isinstance(
            predictions,
            dict
        ):
            valid_rows = False
            break

    # --------------------------------------------------------
    # Evaluate each candidate
    # --------------------------------------------------------

    results = []

    for candidate in stored_candidates:

        name = candidate["name"]

        codes = []

        status = candidate[
            "status"
        ]

        # ----------------------------------------------------
        # Frozen status
        # ----------------------------------------------------

        if status != "frozen":
            codes.append(
                "NOT_FROZEN"
            )

        # ----------------------------------------------------
        # Recompute manifest
        # ----------------------------------------------------

        recalculated_inventory, recalculated_bytes, recalculated_digest, manifest_valid = (
            build_inventory(
                {
                    item["name"]: ""
                    for item in []
                }
            )
        )

        # We need to reconstruct the manifest using the actual
        # submitted frozen file inventory. Compare recorded
        # inventory internally instead.
        recorded_inventory = candidate[
            "inventory"
        ]

        manifest_recomputed = True

        if not isinstance(
            recorded_inventory,
            list
        ):
            manifest_recomputed = False
        else:

            calc_total = 0
            rebuilt = []

            for item in recorded_inventory:

                if not isinstance(
                    item,
                    dict
                ):
                    manifest_recomputed = False
                    break

                if not {
                    "name",
                    "bytes",
                    "sha256"
                }.issubset(item.keys()):
                    manifest_recomputed = False
                    break

                filename = item["name"]
                byte_count = item["bytes"]
                sha = item["sha256"]

                if not isinstance(
                    filename,
                    str
                ):
                    manifest_recomputed = False
                    break

                if not safe_int(
                    byte_count
                ):
                    manifest_recomputed = False
                    break

                if (
                    not isinstance(
                        sha,
                        str
                    )
                    or len(sha) != 64
                ):
                    manifest_recomputed = False
                    break

                calc_total += byte_count

                rebuilt.append(
                    {
                        "name": filename,
                        "bytes": byte_count,
                        "sha256": sha,
                    }
                )

            if manifest_recomputed:

                rebuilt.sort(
                    key=lambda x: utf8_key(
                        x["name"]
                    )
                )

                manifest_digest = hashlib.sha256(
                    compact_json(
                        rebuilt
                    ).encode("utf-8")
                ).hexdigest()

                if (
                    calc_total
                    != candidate["totalBytes"]
                    or manifest_digest
                    != candidate["packageDigest"]
                ):
                    manifest_recomputed = False

        if not manifest_recomputed:
            codes.append(
                "INVALID_MANIFEST"
            )

        # ----------------------------------------------------
        # Predictions
        # ----------------------------------------------------

        aggregate = None
        slice_results = {}
        total_bytes = None
        latency_value = None

        if not valid_rows:
            codes.append(
                "INVALID_PREDICTIONS"
            )

        else:

            correct = 0

            slice_stats = {}

            prediction_valid = True

            for row in rows:

                predictions = row[
                    "predictions"
                ]

                if name not in predictions:
                    prediction_valid = False
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
                    prediction_valid = False
                    break

                if prediction == row[
                    "label"
                ]:
                    correct += 1

                slice_name = row[
                    "slice"
                ]

                if slice_name not in slice_stats:
                    slice_stats[
                        slice_name
                    ] = [0, 0]

                slice_stats[
                    slice_name
                ][1] += 1

                if prediction == row[
                    "label"
                ]:
                    slice_stats[
                        slice_name
                    ][0] += 1

            if not prediction_valid:
                codes.append(
                    "INVALID_PREDICTIONS"
                )

            else:

                aggregate = round(
                    correct / len(rows),
                    12
                )

                for slice_name in sorted(
                    slice_stats.keys(),
                    key=utf8_key
                ):

                    ok, total = slice_stats[
                        slice_name
                    ]

                    slice_results[
                        slice_name
                    ] = round(
                        ok / total,
                        12
                    )

                # Aggregate floor
                if aggregate < float(
                    policy["aggregateFloor"]
                ):
                    codes.append(
                        "AGGREGATE_FLOOR"
                    )

                # Required slices
                for slice_name in sorted(
                    required_slices.keys(),
                    key=utf8_key
                ):

                    if slice_name not in slice_results:
                        codes.append(
                            f"MISSING_SLICE:{slice_name}"
                        )
                        continue

                    if slice_results[
                        slice_name
                    ] < float(
                        required_slices[
                            slice_name
                        ]
                    ):
                        codes.append(
                            f"SLICE_FLOOR:{slice_name}"
                        )

        # ----------------------------------------------------
        # Size
        # ----------------------------------------------------

        if (
            isinstance(
                candidate["totalBytes"],
                int
            )
            and not isinstance(
                candidate["totalBytes"],
                bool
            )
            and candidate["totalBytes"] >= 0
        ):
            total_bytes = candidate[
                "totalBytes"
            ]

            if total_bytes > policy[
                "maxBytes"
            ]:
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
                    policy["maxLatencyMs"]
                ):
                    codes.append(
                        "LATENCY_LIMIT"
                    )

        # ----------------------------------------------------
        # Final status
        # ----------------------------------------------------

        codes = unique_sorted(codes)

        admitted = (
            len(codes) == 0
            and status == "frozen"
            and manifest_recomputed
            and valid_rows
            and aggregate is not None
            and total_bytes is not None
            and latency_value is not None
        )

        results.append(
            {
                "name": name,
                "aggregate": aggregate,
                "slices": slice_results,
                "totalBytes": total_bytes,
                "latencyMs": latency_value,
                "admitted": admitted,
                "reasonCodes": codes,
            }
        )

    # --------------------------------------------------------
    # Result ordering: candidateOrder
    # --------------------------------------------------------

    order_index = {
        name: i
        for i, name in enumerate(
            candidate_order
        )
    }

    results.sort(
        key=lambda r: (
            order_index.get(
                r["name"],
                len(candidate_order)
            ),
            utf8_key(r["name"])
        )
    )

    # --------------------------------------------------------
    # Choose winner
    # --------------------------------------------------------

    admitted = [
        result
        for result in results
        if result["admitted"]
    ]

    if admitted:

        candidate_order_position = {
            name: index
            for index, name in enumerate(
                candidate_order
            )
        }

        winner = sorted(
            admitted,
            key=lambda r: (
                r["totalBytes"],
                float(r["latencyMs"]),
                candidate_order_position[
                    r["name"]
                ],
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
        "packageManifest": package_manifest,
    }, 200


# ============================================================
# ROUTE
# ============================================================

@app.get("/")
def health():
    return {"status": "ok"}


@app.post("/quantize")
async def quantize(payload: dict):

    if not isinstance(
        payload,
        dict
    ):
        return JSONResponse(
            status_code=400,
            content={
                "error": "INVALID_INPUT"
            }
        )

    phase = payload.get(
        "phase"
    )

    # ========================================================
    # FREEZE
    # ========================================================

    if phase == "freeze":

        freeze_id = payload.get(
            "freezeId"
        )

        # Replay/conflict.
        if (
            isinstance(
                freeze_id,
                str
            )
            and freeze_id in FREEZES
        ):

            fingerprint = freeze_fingerprint(
                payload
            )

            if (
                fingerprint
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

        # Only valid freeze requests reserve IDs.
        FREEZES[freeze_id] = {
            "fingerprint":
                freeze_fingerprint(
                    payload
                ),
            "response": result,
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
