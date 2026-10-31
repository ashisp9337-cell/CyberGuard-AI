"""Upgrade #8 (31 Oct): the 2026 link trainer moves its test days with the collection and compares the new model with
the installed one without touching any model file."""
import os

import pytest

pytest.importorskip("sklearn")

from app.detectors import link_2026 as L  # noqa: E402
from app.ml.training import train_link_2026 as T  # noqa: E402


def test_test_days_are_the_last_week_of_the_collection():
    rows = [{"time": "2026-10-03T10:00:00Z"}, {"time": "2026-10-30T23:59:00Z"}, {"time": "2026-10-20T08:00:00Z"}]
    assert T.split_days(rows) == ("2026-10-22", "2026-10-24")          # calibration 22-23 Oct, test 24-30 Oct


def test_explicit_dates_reproduce_the_first_split():
    assert T.split_days([{"time": "2026-10-30"}], "2026-10-12", "2026-10-14") == ("2026-10-12", "2026-10-14")


def test_scoring_with_a_bundle_changes_nothing_on_disk():
    before = os.path.getmtime(L.MODEL_PATH) if os.path.exists(L.MODEL_PATH) else None
    loader = L.load_model
    T.engine_scores(["https://example.com/"], None)
    assert L.load_model is loader                                     # the real loader is put back
    assert (os.path.getmtime(L.MODEL_PATH) if os.path.exists(L.MODEL_PATH) else None) == before
