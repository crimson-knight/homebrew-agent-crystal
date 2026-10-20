"""Check exact typed caller snapshots before comparing original and candidate bytes."""
import hashlib, json

CASES = (
    "numeric_string", "unsupported_boolean", "invalid_numeric_string",
    "nullable_boolean_nil", "nullable_boolean_text", "nullable_integer_nil",
    "multiple_invalid_fields", "typed_setter_raw_reset", "separate_assign_attributes",
    "separate_named_constructor", "concrete_validator_receivers", "second_model_receiver",
)
MARKER = "ATLAS_CHECKED_CALLER_OBSERVATIONS="
FIELDS = {"case_id", "first_name", "age", "active", "raw_age", "age_change", "list_of_errors"}
ERROR_FIELDS = {"field", "error_class", "message", "error_type"}

def require(value, message):
    if not value:
        raise RuntimeError(message)

def scalar(value):
    return value is None or type(value) in (bool, int, str)

def verify_observations(value):
    require(type(value) is dict and set(value) == {"schema_version", "list_of_observations"} and
            type(value["schema_version"]) is int and value["schema_version"] == 1,
            "Caller observation schema differs")
    rows = value["list_of_observations"]
    require(type(rows) is list and all(type(row) is dict for row in rows) and
            [row.get("case_id") for row in rows] == list(CASES),
            "Exact executed caller observation roster/order differs")
    for row in rows:
        require(type(row) is dict and set(row) == FIELDS, "Caller observation field roster differs")
        require(row["first_name"] is None and (row["age"] is None or type(row["age"]) is int) and
                (row["active"] is None or type(row["active"]) is bool) and scalar(row["raw_age"]),
                "Caller typed scalar values differ")
        pair = row["age_change"]
        require(pair is None or type(pair) is list and len(pair) == 2 and all(scalar(v) for v in pair),
                "Caller typed dirty pair differs")
        require(type(row["list_of_errors"]) is list, "Ordered caller error array is required")
        for error in row["list_of_errors"]:
            require(type(error) is dict and set(error) == ERROR_FIELDS and
                    type(error["field"]) is str and error["error_class"] == "Grant::ConversionError" and
                    type(error["message"]) is str and bool(error["message"]) and
                    error["error_type"] is None, "Exact conversion error shape/class differs")
    by_case = {row["case_id"]: row for row in rows}
    require(all(row["active"] is None for row in rows
                if row["case_id"] not in ("nullable_boolean_nil", "nullable_boolean_text")),
            "Unassigned nullable Boolean baseline differs")
    for case, age, raw in (("numeric_string", 42, "42"),
                           ("typed_setter_raw_reset", 43, 43),
                           ("separate_assign_attributes", 44, "44"),
                           ("separate_named_constructor", 45, "45"),
                           ("second_model_receiver", 46, "46")):
        row = by_case[case]
        require(row["age"] == age and row["raw_age"] == raw and
                type(row["raw_age"]) is type(raw) and row["list_of_errors"] == [],
                "Known successful caller value/raw/error oracle differs: " + case)
        expected_pair = None if case == "separate_named_constructor" else [None, age]
        require(row["age_change"] == expected_pair, "Known dirty baseline oracle differs: " + case)
    for case, active in (("nullable_boolean_nil", False), ("nullable_boolean_text", True)):
        row = by_case[case]
        require(row["active"] is active and row["age"] is None and row["raw_age"] is None and
                row["age_change"] is None and row["list_of_errors"] == [],
                "Nullable Boolean column oracle differs: " + case)
    row = by_case["nullable_integer_nil"]
    require(row["age"] is row["raw_age"] is row["age_change"] is None and
            row["list_of_errors"] == [], "Nullable integer oracle differs")
    for case, raw in (("unsupported_boolean", False), ("invalid_numeric_string", "many"),
                      ("multiple_invalid_fields", "many"), ("concrete_validator_receivers", False)):
        row = by_case[case]
        require(row["age"] is None and row["raw_age"] == raw and type(row["raw_age"]) is type(raw) and
                row["age_change"] is None, "Known rejected caller state/raw oracle differs: " + case)
        expected_fields = ["first_name", "age"] if case == "multiple_invalid_fields" else ["age"]
        require([error["field"] for error in row["list_of_errors"]] == expected_fields,
                "Original conversion error field order differs: " + case)
    return {"passed": True, "observations": value, "case_count": len(CASES),
            "comparison_scope": "Exact typed values, ordered error class/field/message/type, raw age and dirty pair; caller specs also assert raw Bool input and concrete validator results"}

def verify_stdout(text):
    require(type(text) is str and "\x1b" not in text, "Raw no-color caller stdout is required")
    candidates = [line.rsplit("\r", 1)[-1] for line in text.split("\n")]
    markers = [line[len(MARKER):] for line in candidates if line.startswith(MARKER)]
    require(len(markers) == 1, "Exactly one complete typed caller observation marker is required")
    result = verify_observations(json.loads(markers[0]))
    result["raw_stdout_sha256"] = hashlib.sha256(text.encode()).hexdigest()
    return result

def verify_equal(original, candidate):
    verify_observations(original)
    verify_observations(candidate)
    require(candidate == original, "Exact original/candidate caller observations differ")
    return {"passed": True, "cases": len(CASES), "error_messages_and_order_equal": True,
            "raw_values_and_dirty_pairs_equal": True}
