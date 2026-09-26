import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from teeweaver.discovery import build_discovery_bundle, observe_run, profile_runs
from teeweaver.elements import RunHistory, load_corpus
from teeweaver.events import Event
from teeweaver.secure_trace import parse_secure_lines, profile_secure_gaps


UUID = "5c9edbc3-7b3a-4367-9f83-7c191ae86a37"


class SecureTraceTests(unittest.TestCase):
    def test_native_lines_restore_loader_mapping_and_refcount_events(self):
        lines = [
            f"D/LD:  ldelf:159 Loading TS {UUID}\n",
            f"D/TC:0 0 ldelf_syscall_open_bin:175 Lookup user SP ELF {UUID} (SP store)\n",
            "D/TC:0 0 ldelf_syscall_open_bin:179 res=0\n",
            f"D/LD:  ldelf:207 ELF ({UUID}) at 0x40037000\n",
            "D/TC:3   mobj_ffa_get_by_cookie:940 cookie 0x1 active: refc 1:2\n",
            "D/TC:3   sp_map_shared:424 SP shared map: mobj=0x1 offs=0 pages=1 requested_va=0\n",
            "D/TC:3   sp_map_shared:451 SP shared map succeeded: mapped_va=0x40000000\n",
        ]
        events, stats = parse_secure_lines(lines)
        self.assertEqual(7, stats.parsed_events)
        self.assertEqual(0, stats.structured_events)
        self.assertEqual({
            "secure_ts_load_issue", "secure_binary_lookup_issue",
            "secure_binary_lookup_complete", "secure_binary_map",
            "secure_mobj_lookup", "secure_sp_map_issue",
            "secure_sp_map_complete",
        }, {event.op for event in events})
        complete = next(
            event for event in events
            if event.op == "secure_binary_lookup_complete"
        )
        self.assertEqual(UUID, complete.get("object"))
        self.assertEqual("SP store", complete.get("store"))
        issue = next(
            event for event in events
            if event.op == "secure_binary_lookup_issue"
        )
        self.assertEqual(issue.get("call"), complete.get("call"))
        mapped = next(
            event for event in events if event.op == "secure_sp_map_complete"
        )
        self.assertEqual("0x1", mapped.get("object"))
        self.assertTrue(all(event.get("order_domain") == "secure-log"
                            for event in events))
        history = RunHistory(
            "native", "diagnostic", "g", "native", tuple(events), {}
        )
        self.assertIn(
            "call-completion",
            {item.family for item in observe_run(history)},
        )

    def test_structured_marker_is_strict_and_preserves_fields(self):
        events, stats = parse_secure_lines([
            'D/TC:0 1 probe:9 TWTRACE {"op":"custom_transition",'
            '"actor":"sp:8002","object":"0xa","phase":"after"}\n'
        ])
        self.assertEqual(1, stats.structured_events)
        self.assertEqual("custom_transition", events[0].op)
        self.assertEqual("sp:8002", events[0].actor)
        self.assertEqual("after", events[0].get("phase"))
        self.assertEqual("explicit-marker", events[0].get("trace_confidence"))
        with self.assertRaisesRegex(ValueError, "invalid TWTRACE JSON"):
            parse_secure_lines(['D/TC:0 0 probe:9 TWTRACE {bad}\n'])

    def test_scheduler_lifetime_panic_and_sp_identity_records_are_parsed(self):
        lines = [
            f"D/TC:0 0 sp_create_session:297 Loading Secure Partition {UUID}\n",
            "D/TC:0 0 sp_init_uuid:1678 endpoint is 0x8002\n",
            "D/TC:0 0 sp_init_all:2143 Starting SP: 0x8002\n",
            "D/TC:? 1 do_notif:34 sleep thread 1 0x44763a58\n",
            "D/TC:? 0 do_notif:34 wake  thread 1 0x44763a58\n",
            "D/TC:? 0 thread_rpc_free:2304 freeing cookie 0x100000000002\n",
            "D/TC:3 1 ffa_inactivate:800 cookie 0x100000000000 was resurrected\n",
            "D/TC:? 0 tee_ta_close_session:513 id 7\n",
            "D/TC:? 0 tee_ta_close_session:527 Destroy session\n",
            "D/TC:? 0 user_ta_enter:196 tee_user_ta_enter: TA panicked with code 0xbeef\n",
            "D/TC:? 0 maybe_release_ta_ctx:696 Releasing panicked TA ctx\n",
            "D/TC:? 0 ldelf_load_ldelf:110 ldelf load address 0x40008000\n",
            f"D/TC:? 0 tee_ta_init_pseudo_ta_session:303 Lookup pseudo TA {UUID}\n",
            "D/TC:0 0 test_wd_callback:1 WD call_count 7, timeout_count 2\n",
            "D/TC:0 0 wd_ndrv_yielding_cb:1 Clearing pending\n",
            "E/SPM-TEST2: ffa_partition_info_get_process:188 ffa_partition_info_get(): unknown error -9\n",
        ]
        events, _ = parse_secure_lines(lines)
        ops = [event.op for event in events]
        self.assertEqual([
            "secure_sp_create", "secure_sp_endpoint_bind", "secure_sp_start",
            "secure_thread_sleep", "secure_thread_wake", "secure_rpc_free",
            "secure_ffa_resurrect", "secure_session_close_issue",
            "secure_session_destroy_complete", "secure_ta_panic_issue",
            "secure_ta_panic_release_complete",
            "secure_ldelf_runtime_map", "secure_pseudo_ta_lookup",
            "secure_watchdog_state", "secure_watchdog_pending_clear",
            "secure_sp_partition_info_error",
        ], ops)
        binding = events[1]
        self.assertEqual(UUID, binding.get("object"))
        self.assertEqual("0x8002", binding.get("endpoint"))
        self.assertEqual("secure:TC", events[3].get("process"))
        self.assertNotEqual(events[3].actor, events[4].actor)
        self.assertEqual(events[7].get("call"), events[8].get("call"))
        self.assertEqual(events[9].get("call"), events[10].get("call"))

    def test_loading_ts_starts_a_new_store_fallback_chain(self):
        lines = [
            f"D/LD:  ldelf:159 Loading TS {UUID}\n",
            f"D/TC:? 0 ldelf_syscall_open_bin:163 Lookup user TA ELF {UUID} (early TA)\n",
            "D/TC:? 0 ldelf_syscall_open_bin:167 res=0xffff0008\n",
            f"D/TC:? 0 ldelf_syscall_open_bin:163 Lookup user TA ELF {UUID} (REE)\n",
            "D/TC:? 0 ldelf_syscall_open_bin:167 res=0xffff0008\n",
            f"D/LD:  ldelf:159 Loading TS {UUID}\n",
            f"D/TC:? 0 ldelf_syscall_open_bin:163 Lookup user TA ELF {UUID} (REE)\n",
            "D/TC:? 0 ldelf_syscall_open_bin:167 res=0\n",
        ]
        events, _ = parse_secure_lines(lines)
        completions = [
            event for event in events
            if event.op.startswith("secure_binary_lookup_complete")
        ]
        self.assertEqual(completions[0].get("call"), completions[1].get("call"))
        self.assertNotEqual(completions[1].get("call"), completions[2].get("call"))

    def test_gap_profiler_excludes_parsed_lines_and_normalizes_values(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "secure.log"
            path.write_text("".join((
                f"D/LD:  ldelf:159 Loading TS {UUID}\n",
                "D/TC:0 0 unknown_boundary:7 object 0x1234 generation 91\n",
                "D/TC:1 2 unknown_boundary:7 object 0xabcd generation 92\n",
                "plain console output\n",
            )), encoding="utf-8")
            report = profile_secure_gaps([path])
        self.assertEqual(4, report["lines"])
        self.assertEqual(3, report["callsite_lines"])
        self.assertEqual(1, report["parsed_lines"])
        self.assertEqual(2, report["unmodeled_callsite_lines"])
        self.assertEqual(1, report["returned_gaps"])
        gap = report["gaps"][0]
        self.assertEqual(2, gap["occurrences"])
        self.assertEqual("unknown_boundary", gap["function"])
        self.assertEqual("object <hex> generation <int>", gap["template"])

    def test_loader_store_fallback_and_refcount_shapes_are_discovered(self):
        events = (
            Event(1, "secure_binary_lookup_complete_error", "secure:TC:0", {
                "source": "secure-log", "order_domain": "secure-log",
                "object": UUID, "store": "early TA", "result": 1,
                "call": "load:1",
            }),
            Event(2, "secure_binary_lookup_complete", "secure:TC:0", {
                "source": "secure-log", "order_domain": "secure-log",
                "object": UUID, "store": "REE", "result": 0,
                "call": "load:1",
            }),
            Event(3, "secure_mobj_lookup", "secure:TC:0", {
                "source": "secure-log", "order_domain": "secure-log",
                "object": "0x10", "refcount_local": 1,
                "refcount_global": 2,
            }),
            Event(4, "secure_mobj_lookup", "secure:TC:0", {
                "source": "secure-log", "order_domain": "secure-log",
                "object": "0x10", "refcount_local": 0,
                "refcount_global": 1,
            }),
            Event(5, "secure_ffa_resurrect", "secure:TC:1", {
                "source": "secure-log", "order_domain": "secure-log",
                "object": "0x10",
            }),
            Event(6, "secure_mobj_lookup", "secure:TC:1", {
                "source": "secure-log", "order_domain": "secure-log",
                "object": "0x10", "refcount_local": 1,
                "refcount_global": 2,
            }),
            Event(7, "secure_rpc_free", "secure:TC:0", {
                "source": "secure-log", "order_domain": "secure-log",
                "object": "0x20",
            }),
            Event(8, "secure_mobj_lookup", "secure:TC:1", {
                "source": "secure-log", "order_domain": "secure-log",
                "object": "0x20", "refcount_local": 1,
                "refcount_global": 1,
            }),
            Event(9, "secure_thread_sleep", "secure:TC:0", {
                "source": "secure-log", "order_domain": "secure-log",
                "object": "0x30", "target_thread": "1",
            }),
            Event(10, "secure_thread_wake", "secure:TC:1", {
                "source": "secure-log", "order_domain": "secure-log",
                "object": "0x30", "target_thread": "1",
            }),
        )
        run = RunHistory("secure", "diagnostic", "g", "p", events, {})
        families = {item.family for item in observe_run(run)}
        self.assertIn("store-fallback", families)
        self.assertIn("refcount-transition", families)
        self.assertIn("resurrection-transition", families)
        self.assertIn("terminal-followup", families)
        self.assertIn("wait-transition", families)
        self.assertTrue(any(
            item.key.endswith("sleep>wake:cross-executor")
            for item in observe_run(run) if item.family == "wait-transition"
        ))

    def test_distinct_order_domains_never_create_cross_stream_sequence(self):
        events = (
            Event(1, "object_verify", "normal", {
                "source": "normal-jsonl", "order_domain": "normal-jsonl",
                "object": "same", "digest": "a", "call": "x",
            }),
            Event(2, "rpc_issue", "normal", {
                "source": "normal-jsonl", "order_domain": "normal-jsonl",
                "call": "pending",
            }),
            Event(3, "object_consume", "secure", {
                "source": "secure-log", "order_domain": "secure-log",
                "object": "same", "digest": "b", "call": "pending",
            }),
        )
        run = RunHistory("mixed", "diagnostic", "g", "p", events, {})
        observations = observe_run(run)
        self.assertNotIn("byte-continuity", {item.family for item in observations})
        self.assertFalse(any(item.family == "order" for item in observations))
        profile = profile_runs([run])[0][0]
        self.assertEqual(1, profile.quality["unmatched_call_issues"])
        self.assertEqual("normal-jsonl",
                         profile.quality["unmatched_calls"][0]["order_domain"])
        bundle = build_discovery_bundle([run], [], spec="synthetic.json")
        before_edges = [
            edge for edge in bundle["semantic_graph"]["edges"]
            if edge["relation"] == "observed-before"
        ]
        self.assertEqual(1, len(before_edges))
        self.assertEqual("normal-jsonl",
                         before_edges[0]["evidence"][0]["order_domain"])

    def test_corpus_loader_merges_secure_log_as_an_independent_stream(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run_dir = root / "result"
            run_dir.mkdir()
            (run_dir / "trace.jsonl").write_text(
                json.dumps({"seq": 1, "op": "rpc_issue", "call": "n"}) + "\n",
                encoding="utf-8",
            )
            (run_dir / "summary.json").write_text("{}\n", encoding="utf-8")
            (run_dir / "secure.log").write_text(
                f"D/LD:  ldelf:159 Loading TS {UUID}\n", encoding="utf-8"
            )
            spec = root / "corpus.json"
            spec.write_text(json.dumps({
                "records": [{"path": "result", "label": "merged"}]
            }), encoding="utf-8")

            run = load_corpus(root, spec, secure_logs=True)[0]
            self.assertEqual(2, len(run.events))
            self.assertEqual(
                {"normal-jsonl": 1, "secure-log": 1},
                run.summary["trace_sources"],
            )
            self.assertEqual(
                {"normal-jsonl", "secure-log"},
                {event.get("order_domain") for event in run.events},
            )
            bundle = build_discovery_bundle([run], [], spec="corpus.json")
            secure = bundle["observation_coverage"]["secure_log"]
            self.assertEqual(1, secure["parsed_events"])
            self.assertEqual(1, secure["lines"])
            self.assertEqual({"loading-ts": 1}, secure["rules"])


if __name__ == "__main__":
    unittest.main()
