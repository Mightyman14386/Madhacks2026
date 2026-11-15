"""Offline tests: no database writes or live Databricks requests."""
import json
import unittest
from unittest.mock import Mock, patch
from databricks.sdk.service.sql import (
    StatementResponse, StatementStatus, StatementState, ResultManifest,
    ResultSchema, ColumnInfo, ResultData,
)
import incidents

ROW = ["43.0731", "-89.4012", "51.5074", "-0.1278", "HIGH", "Example", "203.0.113.2"]

def response(rows=None, state=StatementState.SUCCEEDED, next_chunk=None, truncated=False):
    return StatementResponse(
        statement_id="test-statement", status=StatementStatus(state=state),
        manifest=ResultManifest(schema=ResultSchema(columns=[
            ColumnInfo(name=name, position=i) for i, name in enumerate(incidents.COLUMNS)
        ]), truncated=truncated, total_row_count=len(rows or [])),
        result=ResultData(data_array=rows or [], next_chunk_index=next_chunk),
    )

class ParseTests(unittest.TestCase):
    def test_column_mapping_numeric_values_and_severity(self):
        result = incidents.parse_rows(list(reversed(incidents.COLUMNS)), [list(reversed(ROW))], 20)
        item = result["incidents"][0]
        self.assertEqual(item["latitude_src"], 43.0731)
        self.assertEqual(item["longitude_dest"], -0.1278)
        self.assertEqual(item["severity"], "high")
        self.assertEqual(result["counts"], {"high": 1})

    def test_bad_coordinates_skipped_unknown_severity_retained(self):
        rows = [ROW.copy() for _ in range(6)]
        for row, value in zip(rows, [None, "NaN", "inf", "91", "bad", "0"]):
            row[0] = value
        rows[-1][4] = "unrated"
        result = incidents.parse_rows(incidents.COLUMNS, rows, 20)
        self.assertEqual(result["invalid_rows"], 5)
        self.assertEqual(result["counts"], {"unknown": 1})
        self.assertEqual(len(result["warnings"]), 2)

    def test_missing_schema_fails_without_silent_empty_success(self):
        with self.assertRaises(incidents.IncidentDataError):
            incidents.parse_rows(["lat"], [], 10)

    def test_identical_rows_retained_and_ids_stable_on_reorder(self):
        second = ROW.copy()
        second[4] = "low"
        first = incidents.parse_rows(incidents.COLUMNS, [ROW, second, ROW], 10)
        reordered = incidents.parse_rows(incidents.COLUMNS, [ROW, ROW, second], 10)
        self.assertEqual(len(set(r["id"] for r in first["incidents"])), 3)
        self.assertEqual(sorted(r["id"] for r in first["incidents"]), sorted(r["id"] for r in reordered["incidents"]))

class QueryTests(unittest.TestCase):
    def test_real_sdk_client_configuration_without_network(self):
        # Exercises actual SDK config signatures, but authenticates locally with a dummy PAT.
        from databricks.sdk import WorkspaceClient
        from databricks.sdk.config import Config
        with patch.object(Config, "_resolve_host_metadata"):
            config = Config(host="https://example.cloud.databricks.com", token="offline-test-token",
                        auth_type="pat", scopes=["sql"], http_timeout_seconds=10, retry_timeout_seconds=10)
        with patch("databricks.sdk.config.Config", return_value=config) as constructor:
            client = incidents.workspace_client()
        self.assertIsInstance(client, WorkspaceClient)
        constructor.assert_called_once_with(scopes=["sql"], http_timeout_seconds=10, retry_timeout_seconds=10)
        self.assertEqual(client.config.get_scopes(), ["sql"])

    def test_pending_query_and_chunked_results(self):
        client = Mock()
        api = client.statement_execution
        api.execute_statement.return_value = response(state=StatementState.PENDING)
        api.get_statement.return_value = response([ROW], next_chunk=1)
        api.get_statement_result_chunk_n.return_value = ResultData(data_array=[ROW])
        result = incidents.fetch_incidents(client, sleep=lambda _: None)
        self.assertEqual(len(result["incidents"]), 2)
        args = api.execute_statement.call_args.kwargs
        self.assertEqual(args["warehouse_id"], incidents.config.DATABRICKS_WAREHOUSE_ID)
        self.assertEqual((args["catalog"], args["schema"]), ("workspace", "default"))
        self.assertIn("FROM geospatial_incidents LIMIT 2001", args["statement"])
        api.get_statement_result_chunk_n.assert_called_once_with("test-statement", 1)

    def test_timeout_cancels_statement(self):
        client = Mock()
        client.statement_execution.execute_statement.return_value = response(state=StatementState.RUNNING)
        with self.assertRaises(TimeoutError):
            incidents.fetch_incidents(client, clock=Mock(side_effect=[0, 50]), timeout=45)
        client.statement_execution.cancel_execution.assert_called_once_with("test-statement")

    def test_failed_statement_does_not_leak_sdk_error(self):
        client = Mock()
        client.statement_execution.execute_statement.return_value = response(state=StatementState.FAILED)
        with self.assertRaisesRegex(incidents.IncidentDataError, "did not succeed"):
            incidents.fetch_incidents(client)

    def test_truncated_and_empty_results(self):
        client = Mock()
        client.statement_execution.execute_statement.return_value = response([ROW, ROW])
        result = incidents.fetch_incidents(client, limit=1)
        self.assertEqual(len(result["incidents"]), 1)
        self.assertTrue(result["truncated"])
        client.statement_execution.execute_statement.return_value = response()
        self.assertEqual(incidents.fetch_incidents(client)["incidents"], [])

    def test_repeated_result_chunk_is_rejected(self):
        client = Mock()
        client.statement_execution.execute_statement.return_value = response([ROW], next_chunk=1)
        client.statement_execution.get_statement_result_chunk_n.return_value = ResultData(data_array=[ROW], next_chunk_index=1)
        with self.assertRaisesRegex(incidents.IncidentDataError, "Repeated"):
            incidents.fetch_incidents(client)

    def test_incomplete_results_are_rejected(self):
        for missing in ("following_chunk", "row_array", "too_few_rows"):
            with self.subTest(missing=missing):
                client = Mock()
                result = response([ROW], next_chunk=1 if missing == "following_chunk" else None)
                result.manifest.total_row_count = 2
                if missing == "row_array":
                    result.result = ResultData(data_array=None)
                client.statement_execution.execute_statement.return_value = result
                client.statement_execution.get_statement_result_chunk_n.return_value = None
                with self.assertRaises(incidents.IncidentDataError):
                    incidents.fetch_incidents(client)
                client.statement_execution.cancel_execution.assert_called_once()

    def test_manifest_truncation_is_disclosed(self):
        client = Mock()
        client.statement_execution.execute_statement.return_value = response([ROW], truncated=True)
        result = incidents.fetch_incidents(client)
        self.assertTrue(result["truncated"])
        self.assertTrue(result["warnings"])

class QueuedExecutor:
    def __init__(self):
        self.jobs = []
    def submit(self, callback):
        self.jobs.append(callback)
    def run(self):
        self.jobs.pop(0)()
    def shutdown(self, **kwargs):
        pass

class FeedTests(unittest.TestCase):
    def test_single_flight_cooldown_and_stale_cache(self):
        pool = QueuedExecutor()
        now = [0]
        feed = incidents.IncidentFeed(client_factory=lambda: Mock(), executor=pool, clock=lambda: now[0])
        success = {"incidents": [{"id": "keep-me"}], "fetched_at": "2026-11-15T00:00:00Z"}
        with patch("incidents.fetch_incidents", return_value=success):
            self.assertEqual(feed.snapshot()["state"], "loading")
            feed.snapshot()
            self.assertEqual(len(pool.jobs), 1)
            pool.run()
        self.assertEqual(feed.snapshot()["state"], "ready")
        now[0] += incidents.config.DATABRICKS_REFRESH_SECONDS
        self.assertEqual(feed.snapshot()["state"], "refreshing")
        with patch("incidents.fetch_incidents", side_effect=ValueError("secret-do-not-leak")):
            pool.run()
        cached = feed.snapshot()
        self.assertTrue(cached["stale"])
        self.assertEqual(cached["incidents"], success["incidents"])
        self.assertNotIn("secret-do-not-leak", json.dumps(cached))
        self.assertEqual(len(pool.jobs), 0)
        feed.close()

    def test_scope_rejection_is_actionable_without_leaking_client_values(self):
        pool = QueuedExecutor()
        feed = incidents.IncidentFeed(client_factory=lambda: Mock(), executor=pool)
        feed.snapshot()
        with patch("incidents.fetch_incidents", side_effect=ValueError("access_denied: Scopes all-apis are not assigned to the client secret-client-value")):
            pool.run()
        result = feed.snapshot()
        self.assertEqual(result["state"], "error")
        self.assertIn("sql scope", result["message"])
        self.assertNotIn("secret-client-value", json.dumps(result))
        feed.close()

    def test_failure_recovers_and_clears_stale_state(self):
        pool = QueuedExecutor()
        now = [0]
        feed = incidents.IncidentFeed(client_factory=lambda: Mock(), executor=pool, clock=lambda: now[0])
        feed.snapshot()
        with patch("incidents.fetch_incidents", side_effect=TimeoutError()):
            pool.run()
        self.assertEqual(feed.snapshot()["state"], "error")
        now[0] += incidents.config.DATABRICKS_REFRESH_SECONDS
        feed.snapshot()
        with patch("incidents.fetch_incidents", return_value={"incidents": [], "fetched_at": "now"}):
            pool.run()
        restored = feed.snapshot()
        self.assertEqual(restored["state"], "ready")
        self.assertFalse(restored["stale"])
        self.assertIsNone(restored["message"])
        feed.close()

    def test_api_ready_and_unavailable_status_without_starting_lifespan(self):
        import server
        with patch.object(server.incidents.incident_feed, "snapshot") as snapshot:
            snapshot.return_value = {"state": "error", "fetched_at": None}
            self.assertEqual(server.get_incidents().status_code, 503)
            snapshot.return_value = {"state": "error", "fetched_at": "previous", "incidents": []}
            self.assertEqual(server.get_incidents().status_code, 200)
            snapshot.return_value = {"state": "loading", "fetched_at": None}
            self.assertEqual(server.get_incidents().status_code, 200)

if __name__ == "__main__":
    unittest.main()
