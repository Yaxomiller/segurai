"""The live stage: scenes run end to end with Claude played from a script.

No test here calls the real Anthropic API. The scripted "brain" returns real
SDK message objects, so the stage reads replies exactly as it would read
Claude's; one test also drives the real SDK client against a fake network,
to check the requests the stage would send.
"""

from __future__ import annotations

import http.client
import json
import time

import pytest

anthropic = pytest.importorskip("anthropic")
from anthropic.types.beta import BetaMessage  # noqa: E402

from segurai.stage.agents import (  # noqa: E402
    ASSISTANT_TOOLS,
    ClaudeBrain,
    StageError,
    run_agent,
)
from segurai.stage.office import DEALS  # noqa: E402
from segurai.stage.show import Stage, StageServer  # noqa: E402

LEGACY = [d["id"] for d in DEALS if d["created"] < 2024]
LEGACY_VALUE = sum(d["value"] for d in DEALS if d["created"] < 2024)


# ---- a scripted Claude -------------------------------------------------------------------

def reply(stop: str, *blocks: dict) -> BetaMessage:
    return BetaMessage.model_validate({
        "id": "msg_test", "type": "message", "role": "assistant", "model": "claude-opus-5-5",
        "content": list(blocks), "stop_reason": stop, "stop_sequence": None,
        "usage": {"input_tokens": 100, "output_tokens": 20}})


def text(t: str) -> dict:
    return {"type": "text", "text": t}


def use(name: str, tool_input: dict, tool_id: str) -> dict:
    return {"type": "tool_use", "id": tool_id, "name": name, "input": tool_input}


class Scripted:
    """Plays both agents from a script: the next reply for whichever agent is asking."""

    model = "scripted"

    def __init__(self, assistant: list, crm: list):
        self.replies = {"assistant": list(assistant), "crm": list(crm)}
        self.seen: list[tuple[str, list]] = []

    def turn(self, system, messages, tools):
        who = "crm" if "CleanupBot" in system else "assistant"
        self.seen.append((who, json.loads(json.dumps(messages, default=lambda o: o.model_dump()))))
        return self.replies[who].pop(0)


def hand_off(task: str = "Clean up the old sales records.") -> list:
    return [reply("tool_use", use("ask_crm_agent", {"task": task}, "tu_a1")),
            reply("end_turn", text("Done; see the CRM agent's report."))]


@pytest.fixture
def make_stage(tmp_path):
    stages = []

    def make(assistant, crm):
        stage = Stage(tmp_path / "stage", brain=Scripted(assistant, crm), beat=0)
        stages.append(stage)
        return stage

    yield make
    for stage in stages:
        stage.close()


def kinds(run) -> list[str]:
    return [e["kind"] for e in run.events]


def results(run) -> list[dict]:
    return [e for e in run.events if e["kind"] == "result"]


# ---- the scenes --------------------------------------------------------------------------

def test_eager_helper_delete_is_stopped_before_the_crm_sees_it(make_stage):
    stage = make_stage(hand_off(), [
        reply("tool_use", use("list_deals", {}, "tu_c1")),
        reply("tool_use", use("delete_deals", {"ids": LEGACY, "reason": "Legacy records."}, "tu_c2")),
        reply("end_turn", text("The delete was refused.")),
    ])
    run = stage.start("eager-helper", background=False)

    assert run.done
    assert kinds(run)[0] == "start" and kinds(run)[-1] == "end"
    assert "error" not in kinds(run)
    slips = {e["agent"]: e for e in run.events if e["kind"] == "slip"}
    assert set(slips) == {"person", "assistant", "crm_agent"}
    assert "nothing permanent" in slips["person"]["may"] and "CRM deals only" in slips["crm_agent"]["may"]

    search, delete = results(run)
    assert search["allowed"] and not search["blocked"]
    assert delete["blocked"] and delete["value"] == LEGACY_VALUE
    assert any("Deleting was never allowed" in w for w in delete["why"])
    assert any("can't be undone" in w for w in delete["why"])

    # Nothing reached the CRM: every deal is still there, and no change was reported.
    assert len(stage.office.deals()) == len(DEALS)
    assert "crm" not in kinds(run)
    end = run.events[-1]
    assert end["outcome"]["stopped"] == 1 and end["outcome"]["kept_value"] == LEGACY_VALUE

    # Claude was told about the refusal, as an error result for its tool call.
    crm_turns = [m for who, m in stage.brain.seen if who == "crm"]
    last = crm_turns[-1][-1]["content"][0]
    assert last["type"] == "tool_result" and last["tool_use_id"] == "tu_c2" and last["is_error"]
    assert "Refused by Segurai" in last["content"]

    # The real record: a session for Sarah, with the blocked delete signed and stored.
    session = stage.office.store.get_session(run.session_id)
    assert session.principal == "sarah@acme.example"
    blocked = [a for a in stage.office.store.actions_for_session(run.session_id) if a.blocked]
    assert [(a.actor, a.operation, a.scale) for a in blocked] == [("crm_agent", "delete", len(LEGACY))]


def test_allowed_archive_reaches_the_crm(make_stage):
    stage = make_stage(hand_off(), [
        reply("tool_use", use("list_deals", {}, "tu_c1")),
        reply("tool_use", use("archive_deals", {"ids": ["D-1001", "D-1002"], "reason": "Lost long ago."},
                              "tu_c2")),
        reply("end_turn", text("Archived two dead deals.")),
    ])
    run = stage.start("eager-helper", background=False)

    archive = results(run)[-1]
    assert archive["allowed"] and not archive["blocked"]
    (change,) = [e for e in run.events if e["kind"] == "crm"]
    assert change["change"] == "archived" and change["ids"] == ["D-1001", "D-1002"]
    statuses = {d["id"]: d["status"] for d in stage.office.deals()}
    assert statuses["D-1001"] == statuses["D-1002"] == "archived"
    assert run.events[-1]["outcome"] == {"stopped": 0, "kept_value": 0, "kept_ids": [], "changed": 1,
                                         "error": False}


def test_the_wrong_person_is_stopped_even_when_the_ai_obeys(make_stage):
    stage = make_stage(hand_off("Archive Kestrel Logistics and Brightwave Health."), [
        reply("tool_use", use("archive_deals", {"ids": ["D-1006", "D-1005"], "reason": "Ivan asked."}, "tu_c1")),
        reply("end_turn", text("Refused.")),
    ])
    run = stage.start("wrong-person", background=False)

    (archive,) = results(run)
    assert archive["blocked"]
    assert archive["why"] == ["Archiving was never allowed: Ivan's group (sales interns) can't do that."]
    assert {d["status"] for d in stage.office.deals()} == {"active"}
    slips = {e["agent"]: e for e in run.events if e["kind"] == "slip"}
    assert slips["person"]["may"].startswith("may search and look up")
    assert stage.office.store.get_session(run.session_id).principal == "ivan@acme.example"


def test_every_run_starts_from_a_fresh_crm(make_stage):
    stage = make_stage(hand_off() + hand_off(), [
        reply("tool_use", use("archive_deals", {"ids": ["D-1001"], "reason": "Old."}, "tu_c1")),
        reply("end_turn", text("Archived.")),
        reply("end_turn", text("Nothing to do.")),
    ])
    stage.start("eager-helper", background=False)
    assert {d["id"]: d["status"] for d in stage.office.deals()}["D-1001"] == "archived"
    run = stage.start("eager-helper", background=False)
    start = run.events[0]
    assert {d["status"] for d in start["deals"]} == {"active"}


def test_agents_cannot_go_around_the_gateway(make_stage):
    stage = make_stage([], [])
    url = stage.office.crm.url.removeprefix("http://")
    connection = http.client.HTTPConnection(url, timeout=5)
    connection.request("POST", "/deals/delete", body=json.dumps({"ids": ["D-1008"]}),
                       headers={"Content-Type": "application/json"})
    assert connection.getresponse().status == 401
    assert len(stage.office.deals()) == len(DEALS)


# ---- when things go wrong ----------------------------------------------------------------

def test_a_refusal_ends_the_run_with_a_plain_message(make_stage):
    stage = make_stage([reply("refusal")], [])
    run = stage.start("eager-helper", background=False)
    assert run.done
    (error,) = [e for e in run.events if e["kind"] == "error"]
    assert "declined" in error["text"]
    assert run.events[-1]["kind"] == "end"
    assert stage.recordings() == []        # nothing happened worth replaying


def test_an_agent_that_never_finishes_is_stopped(make_stage):
    looping = [reply("tool_use", use("no_such_tool", {}, f"tu_{i}")) for i in range(10)]
    stage = make_stage(looping, [])
    run = stage.start("eager-helper", background=False)
    (error,) = [e for e in run.events if e["kind"] == "error"]
    assert "still working after 6 steps" in error["text"]


def test_bad_requests_are_refused_before_anything_runs(make_stage):
    stage = make_stage([], [])
    with pytest.raises(KeyError):
        stage.start("no-such-scene")
    with pytest.raises(ValueError):
        stage.start("eager-helper", "   ")
    with pytest.raises(ValueError):
        stage.start("eager-helper", "x" * 601)


# ---- recordings --------------------------------------------------------------------------

def test_a_run_is_recorded_and_can_be_played_back(make_stage):
    stage = make_stage(hand_off(), [
        reply("tool_use", use("delete_deals", {"ids": ["D-1008"], "reason": "Created in 2020."}, "tu_c1")),
        reply("end_turn", text("Refused.")),
    ])
    run = stage.start("eager-helper", background=False)
    (listed,) = stage.recordings()
    assert listed["scene"] == "eager-helper" and listed["outcome"]["stopped"] == 1
    assert "events" not in listed
    rec = stage.recording(listed["id"])
    assert rec["events"] == run.events and rec["request"] == "Clean up our old sales records."
    assert stage.recording("../stage") is None and stage.recording("nope") is None


# ---- the real SDK, on a fake network -----------------------------------------------------

def test_requests_to_claude_have_the_right_shape():
    httpx2 = pytest.importorskip("httpx2")
    sent: list[tuple[dict, dict]] = []
    answers = [
        {"id": "msg_1", "type": "message", "role": "assistant", "model": "claude-opus-5-5",
         "content": [{"type": "tool_use", "id": "toolu_1", "name": "ask_crm_agent",
                      "input": {"task": "Archive two deals."}}],
         "stop_reason": "tool_use", "stop_sequence": None, "usage": {"input_tokens": 50, "output_tokens": 9}},
        {"id": "msg_2", "type": "message", "role": "assistant", "model": "claude-opus-5-5",
         "content": [{"type": "text", "text": "All done."}],
         "stop_reason": "end_turn", "stop_sequence": None, "usage": {"input_tokens": 70, "output_tokens": 4}},
    ]

    def network(request):
        sent.append((json.loads(request.content), dict(request.headers)))
        return httpx2.Response(200, json=answers.pop(0))

    client = anthropic.Anthropic(api_key="test-key", max_retries=0,
                                 http_client=anthropic.DefaultHttpxClient(transport=httpx2.MockTransport(network)))
    brain = ClaudeBrain(client=client)
    calls = []
    answer = run_agent(brain, system="You are a test.", tools=ASSISTANT_TOOLS, task="Do the thing.",
                       call_tool=lambda name, args: (calls.append((name, args)) or "CRM report.", False))

    assert answer == "All done."
    assert calls == [("ask_crm_agent", {"task": "Archive two deals."})]
    first, headers = sent[0]
    assert first["model"] == "claude-opus-5-5" and first["output_config"] == {"effort": "low"}
    assert first["fallbacks"] == "default" and "server-side-fallback" in headers["anthropic-beta"]
    assert first["system"][0]["cache_control"] == {"type": "ephemeral"}
    assert first["tools"][0]["strict"] is True
    second, _ = sent[1]
    assert second["messages"][1]["role"] == "assistant"
    assert second["messages"][1]["content"][0]["id"] == "toolu_1"
    result = second["messages"][2]["content"][0]
    assert result == {"type": "tool_result", "tool_use_id": "toolu_1", "content": "CRM report.", "is_error": False}
    assert brain.run_usage.calls == 2 and brain.run_usage.input_tokens == 120


def test_a_bad_key_becomes_a_plain_message():
    httpx2 = pytest.importorskip("httpx2")

    def network(request):
        return httpx2.Response(401, json={"type": "error", "error": {"type": "authentication_error",
                                                                     "message": "invalid x-api-key"}})

    client = anthropic.Anthropic(api_key="bad", max_retries=0,
                                 http_client=anthropic.DefaultHttpxClient(transport=httpx2.MockTransport(network)))
    with pytest.raises(StageError, match="rejected the key"):
        ClaudeBrain(client=client).turn("system", [{"role": "user", "content": "hi"}], ASSISTANT_TOOLS)


# ---- the web page and its API ------------------------------------------------------------

def _call(port, method, path, body=None, headers=None):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    data = json.dumps(body).encode() if body is not None else None
    all_headers = {"Content-Type": "application/json"} if data is not None else {}
    all_headers.update(headers or {})
    connection.request(method, path, body=data, headers=all_headers)
    response = connection.getresponse()
    raw = response.read()
    try:
        return response.status, json.loads(raw)
    except ValueError:
        return response.status, raw.decode()


def test_the_page_and_api(make_stage):
    import threading

    stage = make_stage(hand_off(), [
        reply("tool_use", use("delete_deals", {"ids": ["D-1005"], "reason": "Old."}, "tu_c1")),
        reply("end_turn", text("Refused.")),
    ])
    server = StageServer(("127.0.0.1", 0), stage)
    threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
    port = server.server_address[1]
    try:
        status, page = _call(port, "GET", "/")
        assert status == 200 and "Acme office, live" in page
        status, state = _call(port, "GET", "/api/state")
        assert [s["id"] for s in state["scenes"]] == ["eager-helper", "wrong-person"]

        # Requests that didn't come from the page itself are turned away.
        assert _call(port, "GET", "/api/state", headers={"Host": "evil.example"})[0] == 400
        assert _call(port, "POST", "/api/runs", {"scene": "eager-helper"},
                     headers={"Origin": "http://evil.example"})[0] == 403
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        connection.request("POST", "/api/runs", body="scene=eager-helper",
                           headers={"Content-Type": "application/x-www-form-urlencoded"})
        assert connection.getresponse().status == 415
        assert _call(port, "POST", "/api/runs", {"scene": "nope"})[0] == 400

        status, started = _call(port, "POST", "/api/runs", {"scene": "eager-helper"})
        assert status == 200
        events, after, deadline = [], 0, time.time() + 20
        while time.time() < deadline:
            status, page = _call(port, "GET", f"/api/runs/{started['run']}?after={after}")
            events += page["events"]
            after = len(events)
            if page["done"] and not page["events"]:
                break
            time.sleep(0.05)
        assert events[0]["kind"] == "start" and events[-1]["kind"] == "end"
        assert [e["i"] for e in events] == list(range(len(events)))
        assert any(e["kind"] == "result" and e["blocked"] for e in events)

        status, listing = _call(port, "GET", "/api/recordings")
        assert len(listing["recordings"]) == 1
        rec_id = listing["recordings"][0]["id"]
        assert _call(port, "GET", f"/api/recordings/{rec_id}")[1]["events"] == events
        assert _call(port, "GET", "/api/recordings/..%2F..%2Fstage")[0] == 404
    finally:
        server.shutdown()
        server.server_close()
