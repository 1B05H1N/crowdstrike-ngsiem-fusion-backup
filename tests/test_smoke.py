"""Offline smoke tests (no API calls). Run: python3 -m unittest discover -s tests -p 'test_*.py' -v"""
from __future__ import annotations

import os
import sys
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


_REMOTE_ENV_KEYS = (
    "BACKUP_REMOTE_DIR",
    "OUTPUT_SHARE",
    "BACKUP_REMOTE_PUBLISH",
    "BACKUP_REMOTE_SUBDIR",
    "BACKUP_REMOTE_MAX_ARCHIVES",
)


def _stash_remote_env() -> dict:
    return {k: os.environ.pop(k, None) for k in _REMOTE_ENV_KEYS}


def _restore_remote_env(saved: dict) -> None:
    for k, v in saved.items():
        if v is not None:
            os.environ[k] = v
        else:
            os.environ.pop(k, None)


class TestBackupRemotePublish(unittest.TestCase):
    def setUp(self) -> None:
        p = patch("tools.backup_remote_publish.console.print")
        self.addCleanup(p.stop)
        p.start()

    def test_validate_date_stamp(self) -> None:
        from tools.backup_remote_publish import _validate_date_stamp, _rel_path_safe

        self.assertTrue(_validate_date_stamp("2026-04-05"))
        self.assertFalse(_validate_date_stamp("not-a-date"))
        self.assertFalse(_validate_date_stamp("../etc/passwd"))
        self.assertFalse(_validate_date_stamp("2026-13-40"))
        self.assertTrue(_rel_path_safe("workflows/a.yaml"))
        self.assertFalse(_rel_path_safe("../../x"))
        self.assertFalse(_rel_path_safe(""))
        self.assertFalse(_rel_path_safe("a/../b"))
        self.assertFalse(_rel_path_safe("/abs/path"))
        self.assertTrue(_rel_path_safe("ngsiem_lookups/falcon/file.csv"))

    def test_publish_none_without_remote_root(self) -> None:
        from tools.backup_remote_publish import publish_compressed_backup

        saved = _stash_remote_env()
        try:
            self.assertIsNone(
                publish_compressed_backup("backups", "2026-04-05", {"command": "test"})
            )
        finally:
            _restore_remote_env(saved)

    def test_publish_skipped_when_remote_set_but_not_enabled(self) -> None:
        import tempfile

        from tools.backup_remote_publish import publish_compressed_backup

        with tempfile.TemporaryDirectory() as share:
            with tempfile.TemporaryDirectory() as out:
                day = Path(out) / "2026-04-05"
                day.mkdir(parents=True, exist_ok=True)
                (day / "sample.txt").write_text("hello", encoding="utf-8")
                saved = _stash_remote_env()
                try:
                    os.environ["OUTPUT_SHARE"] = share
                    r = publish_compressed_backup(
                        str(out), "2026-04-05", {"command": "test"}
                    )
                    self.assertIsInstance(r, dict)
                    self.assertTrue(r.get("skipped"))
                    self.assertEqual(r.get("reason"), "remote_publish_disabled")
                    archives = Path(share) / "crowdstrike-backup" / "archives"
                    self.assertFalse(archives.exists())
                finally:
                    _restore_remote_env(saved)

    def test_publish_writes_zip_when_enabled(self) -> None:
        import tempfile

        from tools.backup_remote_publish import publish_compressed_backup

        with tempfile.TemporaryDirectory() as share:
            with tempfile.TemporaryDirectory() as out:
                day = Path(out) / "2026-04-05"
                day.mkdir(parents=True, exist_ok=True)
                (day / "sample.txt").write_text("hello", encoding="utf-8")
                saved = _stash_remote_env()
                try:
                    os.environ["OUTPUT_SHARE"] = share
                    os.environ["BACKUP_REMOTE_PUBLISH"] = "1"
                    r = publish_compressed_backup(
                        str(out), "2026-04-05", {"command": "test"}
                    )
                    self.assertIsInstance(r, dict)
                    self.assertNotIn("skipped", r)
                    zp = Path(r["zip_path"])
                    self.assertTrue(zp.is_file())
                    with zipfile.ZipFile(zp, "r") as zf:
                        names = set(zf.namelist())
                    self.assertIn("sample.txt", names)
                    self.assertTrue(any(n.startswith("audit_") for n in names))
                finally:
                    _restore_remote_env(saved)

    def test_sanitize_run_context(self) -> None:
        from tools.backup_remote_publish import _sanitize_run_context

        raw = {
            "command": "all",
            "client_id": "cid-leak",
            "client_secret": "leak",
            "nested": {"api_key": "x", "ok": 1},
            "items": [{"token": "t"}, 2],
        }
        clean = _sanitize_run_context(raw)
        self.assertEqual(clean["command"], "all")
        self.assertEqual(clean["client_id"], "[redacted]")
        self.assertEqual(clean["client_secret"], "[redacted]")
        self.assertEqual(clean["nested"]["api_key"], "[redacted]")
        self.assertEqual(clean["nested"]["ok"], 1)
        self.assertEqual(clean["items"][0]["token"], "[redacted]")
        self.assertEqual(clean["items"][1], 2)


class TestNgsiemParsersBackup(unittest.TestCase):
    def test_entries_from_list_batch(self) -> None:
        from tools.ngsiem_parsers_backup import _entries_from_list_batch

        self.assertEqual(
            _entries_from_list_batch(
                [
                    {"id": "p1", "name": "My Parser"},
                    {"parser_id": "p2"},
                    {"parserId": "p3", "displayName": "X"},
                    {"ID": "p4", "Name": "Falcon shape"},
                ]
            ),
            [
                ("p1", "My Parser"),
                ("p2", None),
                ("p3", "X"),
                ("p4", "Falcon shape"),
            ],
        )

    def test_resolve_parser_type_passes(self) -> None:
        from tools.ngsiem_parsers_backup import resolve_parser_type_passes

        self.assertEqual(resolve_parser_type_passes("all"), (None,))
        self.assertEqual(resolve_parser_type_passes("custom,ootb"), ("custom", "ootb"))
        self.assertEqual(resolve_parser_type_passes("  OOTB  "), ("ootb",))
        old = os.environ.pop("NGSIEM_PARSER_TYPES", None)
        try:
            self.assertEqual(resolve_parser_type_passes(None), ("custom",))
        finally:
            if old is not None:
                os.environ["NGSIEM_PARSER_TYPES"] = old

    def test_resolve_parser_type_passes_invalid(self) -> None:
        from tools.ngsiem_parsers_backup import resolve_parser_type_passes

        with self.assertRaises(ValueError):
            resolve_parser_type_passes("bogus")


class TestValidateBackupSearches(unittest.TestCase):
    def test_validate_all_ok_with_mocks(self) -> None:
        from unittest.mock import MagicMock, patch

        from tools.validate_backup_searches import validate_backup_api_searches

        ok = {"status_code": 200, "body": {"resources": []}}

        mock_cr = MagicMock()
        mock_cr.query_rules = MagicMock(return_value=ok)
        mock_wf = MagicMock()
        mock_wf.search_definitions = MagicMock(return_value=ok)
        mock_wf.search_activities = MagicMock(return_value=ok)
        mock_wf.search_activities_content = MagicMock(return_value=ok)
        mock_wf.search_triggers = MagicMock(return_value=ok)
        mock_wf.search_executions = MagicMock(return_value=ok)
        mock_ng = MagicMock()
        mock_ng.list_lookup_files = MagicMock(return_value=ok)
        mock_ng.list_parsers = MagicMock(return_value=ok)

        with patch(
            "tools.validate_backup_searches.CorrelationRules", return_value=mock_cr
        ), patch("tools.validate_backup_searches.Workflows", return_value=mock_wf), patch(
            "tools.validate_backup_searches.NGSIEM", return_value=mock_ng
        ):
            r = validate_backup_api_searches(
                "id",
                "sec",
                "us-2",
                "*",
                include_fusion_catalog=True,
                include_ngsiem_lookups=True,
                include_ngsiem_parsers=True,
            )

        self.assertTrue(r["all_ok"])
        self.assertGreaterEqual(len(r["checks"]), 10)
        names = [c["name"] for c in r["checks"]]
        self.assertIn("correlation_rules.query_rules", names)
        self.assertIn("workflows.search_definitions", names)


class TestCliHelpers(unittest.TestCase):
    def test_format_remote_publish_disabled(self) -> None:
        from cli import _format_remote_publish_result

        msg = _format_remote_publish_result(
            {"skipped": True, "reason": "remote_publish_disabled"}
        )
        self.assertIn("BACKUP_REMOTE_PUBLISH", msg)


class TestBackupFingerprints(unittest.TestCase):
    def test_bundle_matches_saved_subset(self) -> None:
        from tools.backup_fingerprints import FORMAT_VERSION, bundle_matches_saved

        saved = {
            "v": FORMAT_VERSION,
            "cloud_region": "us-2",
            "backup_filter": "*",
            "correlation_rules": {"count": 1, "ids_sha256": "a"},
            "workflows": {"count": 0, "meta_sha256": "b"},
        }
        current_rules_only = {
            "v": FORMAT_VERSION,
            "cloud_region": "us-2",
            "backup_filter": "*",
            "correlation_rules": {"count": 1, "ids_sha256": "a"},
        }
        self.assertTrue(bundle_matches_saved(saved, current_rules_only))
        current_rules_only["correlation_rules"] = {"count": 2, "ids_sha256": "a"}
        self.assertFalse(bundle_matches_saved(saved, current_rules_only))

    def test_merge_saved_with_bundle(self) -> None:
        from tools.backup_fingerprints import FORMAT_VERSION, merge_saved_with_bundle

        old = {
            "v": FORMAT_VERSION,
            "cloud_region": "us-2",
            "backup_filter": "*",
            "correlation_rules": {"count": 1, "ids_sha256": "x"},
        }
        new = {
            "v": FORMAT_VERSION,
            "cloud_region": "us-2",
            "workflows": {"count": 2, "meta_sha256": "y"},
        }
        merged = merge_saved_with_bundle(old, new)
        self.assertEqual(merged["correlation_rules"], old["correlation_rules"])
        self.assertEqual(merged["workflows"], new["workflows"])
        self.assertEqual(merged["v"], FORMAT_VERSION)

    def test_bundle_ngsiem_parser_scope_changes_invalidate(self) -> None:
        from tools.backup_fingerprints import FORMAT_VERSION, bundle_matches_saved

        saved = {
            "v": FORMAT_VERSION,
            "cloud_region": "us-2",
            "ngsiem_parsers": {
                "count": 1,
                "repository": "parsers-repository",
                "parser_type_passes": ["custom"],
                "ids_sha256": "abc",
            },
        }
        current = {
            "v": FORMAT_VERSION,
            "cloud_region": "us-2",
            "ngsiem_parsers": {
                "count": 1,
                "repository": "parsers-repository",
                "parser_type_passes": ["ootb"],
                "ids_sha256": "abc",
            },
        }
        self.assertFalse(bundle_matches_saved(saved, current))


class TestValidators(unittest.TestCase):
    def test_sanitize_filename(self) -> None:
        from utils.validators import sanitize_filename

        self.assertEqual(sanitize_filename("My Rule <>"), "My_Rule_")
        self.assertNotIn("/", sanitize_filename("a/b"))
