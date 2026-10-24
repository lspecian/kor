"""Probe a Firestore-compatible server with the operations a typical backend uses.

Usage: FIRESTORE_EMULATOR_HOST=host:port python firestore_probe.py <label> [out.json]
Prints PASS/FAIL per check, optionally writes the results to out.json (to
compare servers, e.g. Kor against the Firestore emulator), and exits non-zero
when a check fails.
"""

import asyncio
import json
import os
import sys
import threading
import time
import uuid

from google.api_core import exceptions as gexc
from google.cloud import firestore
from google.cloud.firestore_v1 import aggregation
from google.cloud.firestore_v1.base_query import FieldFilter, Or

label = sys.argv[1]
out_path = sys.argv[2] if len(sys.argv) > 2 else ""
project = os.environ.get("GOOGLE_CLOUD_PROJECT", "kor-local")
db = firestore.Client(project=project)
run = uuid.uuid4().hex[:8]
root = db.collection(f"probe_{run}")
results: dict[str, str] = {}


def check(name):
    def wrap(fn):
        try:
            detail = fn()
            results[name] = f"PASS {detail if detail is not None else ''}".strip()
        except Exception as e:  # noqa: BLE001 - a probe reports every failure
            results[name] = f"FAIL {type(e).__name__}: {str(e)[:160]}"
        print(f"[{label}] {name}: {results[name]}", flush=True)
        return fn
    return wrap


@check("set_get")
def _():
    root.document("a").set({"n": 1, "s": "x", "tags": ["a", "b"], "nested": {"k": 1, "j": 2}})
    d = root.document("a").get().to_dict()
    assert d["n"] == 1 and d["nested"]["j"] == 2, d


@check("merge_keeps_siblings")
def _():
    root.document("a").set({"nested": {"k": 9}}, merge=True)
    d = root.document("a").get().to_dict()["nested"]
    assert d == {"k": 9, "j": 2}, d


@check("update_dotted_path")
def _():
    root.document("a").update({"nested.j": 5})
    assert root.document("a").get().to_dict()["nested"] == {"k": 9, "j": 5}


@check("sentinels")
def _():
    root.document("a").update({
        "ts": firestore.SERVER_TIMESTAMP,
        "n": firestore.Increment(2),
        "tags": firestore.ArrayUnion(["c"]),
        "s": firestore.DELETE_FIELD,
    })
    root.document("a").update({"tags": firestore.ArrayRemove(["a"])})
    d = root.document("a").get().to_dict()
    assert d["n"] == 3 and d["tags"] == ["b", "c"] and "s" not in d and d["ts"] is not None, d
    return type(d["ts"]).__name__


@check("create_existing_raises")
def _():
    try:
        root.document("a").create({"x": 1})
    except gexc.AlreadyExists:
        return "AlreadyExists"
    raise AssertionError("no error")


@check("update_missing_raises")
def _():
    try:
        root.document("missing").update({"x": 1})
    except gexc.NotFound:
        return "NotFound"
    raise AssertionError("no error")


for i in range(6):
    root.document(f"q{i}").set({"i": i, "group": "even" if i % 2 == 0 else "odd",
                                "tags": [f"t{i}", "all"], "status": ["new", "done", "failed"][i % 3]})


def ids(q):
    return [s.id for s in q.stream()]


@check("where_orderby_limit")
def _():
    r = ids(root.where(filter=FieldFilter("group", "==", "even")).order_by("i", direction="DESCENDING").limit(2))
    assert r == ["q4", "q2"], r


@check("range_filter")
def _():
    r = ids(root.where(filter=FieldFilter("i", ">=", 2)).where(filter=FieldFilter("i", "<", 4)).order_by("i"))
    assert r == ["q2", "q3"], r


@check("in_filter")
def _():
    r = sorted(ids(root.where(filter=FieldFilter("status", "in", ["new", "failed"]))))
    assert r == ["q0", "q2", "q3", "q5"], r


@check("array_contains")
def _():
    assert ids(root.where(filter=FieldFilter("tags", "array_contains", "t3"))) == ["q3"]


@check("array_contains_any")
def _():
    r = sorted(ids(root.where(filter=FieldFilter("tags", "array_contains_any", ["t1", "t4"]))))
    assert r == ["q1", "q4"], r


@check("not_equal")
def _():
    r = sorted(ids(root.where(filter=FieldFilter("status", "!=", "done"))))
    assert r == ["q0", "q2", "q3", "q5"], r


@check("not_in")
def _():
    r = sorted(ids(root.where(filter=FieldFilter("status", "not-in", ["done", "failed"]))))
    assert r == ["q0", "q3"], r


@check("or_filter")
def _():
    r = sorted(ids(root.where(filter=Or([FieldFilter("i", "==", 1), FieldFilter("status", "==", "failed")]))))
    assert r == ["q1", "q2", "q5"], r


@check("start_after_cursor")
def _():
    first = list(root.order_by("i").limit(2).stream())
    r = ids(root.order_by("i").start_after(first[-1]).limit(2))
    assert r == ["q2", "q3"], r


@check("collection_group")
def _():
    root.document("p1").collection("items").document("x").set({"v": 1})
    root.document("p2").collection("items").document("y").set({"v": 2})
    r = sorted(s.id for s in db.collection_group("items").where(filter=FieldFilter("v", ">", 0)).stream()
               if s.reference.path.startswith(root.id))
    assert r == ["x", "y"], r


@check("count_aggregation")
def _():
    agg = aggregation.AggregationQuery(root.where(filter=FieldFilter("group", "==", "odd")))
    agg.count(alias="c")
    c = agg.get()[0][0].value
    assert c == 3, c


@check("get_all")
def _():
    snaps = list(db.get_all([root.document("q1"), root.document("q2"), root.document("nope")]))
    assert sorted((s.id, s.exists) for s in snaps) == [("nope", False), ("q1", True), ("q2", True)]


@check("list_subcollections")
def _():
    r = [c.id for c in root.document("p1").collections()]
    assert r == ["items"], r


@check("batch")
def _():
    b = db.batch()
    b.set(root.document("b1"), {"v": 1})
    b.update(root.document("q0"), {"batched": True})
    b.delete(root.document("q5"))
    b.commit()
    assert root.document("b1").get().exists and not root.document("q5").get().exists


@check("transaction_rmw")
def _():
    ref = root.document("counter")
    ref.set({"v": 0})

    @firestore.transactional
    def bump(tx):
        snap = ref.get(transaction=tx)
        tx.update(ref, {"v": snap.get("v") + 1})

    for _ in range(3):
        bump(db.transaction())
    assert ref.get().to_dict()["v"] == 3


@check("transaction_contention")
def _():
    ref = root.document("contended")
    ref.set({"v": 0})

    @firestore.transactional
    def bump(tx):
        snap = ref.get(transaction=tx)
        time.sleep(0.05)
        tx.update(ref, {"v": snap.get("v") + 1})

    threads = [threading.Thread(target=lambda: bump(firestore.Client(project=project).transaction())) for _ in range(5)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    v = ref.get().to_dict()["v"]
    assert v == 5, f"lost updates: v={v}"


@check("async_client")
def _():
    async def go():
        adb = firestore.AsyncClient(project=project)
        aref = adb.collection(root.id).document("async1")
        await aref.set({"v": 1, "ts": firestore.SERVER_TIMESTAMP})
        await aref.update({"v": firestore.Increment(1)})
        snap = await aref.get()
        q = [s.id async for s in adb.collection(root.id).where(filter=FieldFilter("group", "==", "even")).order_by("i").stream()]

        @firestore.async_transactional
        async def tx_fn(tx):
            s = await aref.get(transaction=tx)
            tx.update(aref, {"v": s.get("v") * 10})

        await tx_fn(adb.transaction())
        final = (await aref.get()).to_dict()["v"]
        return snap.to_dict()["v"], q, final

    v, q, final = asyncio.run(go())
    assert v == 2 and q == ["q0", "q2", "q4"] and final == 20, (v, q, final)


@check("listener_on_snapshot")
def _():
    seen = []
    done = threading.Event()

    def cb(snaps, changes, read_time):
        seen.append(len(snaps))
        if len(seen) >= 2:
            done.set()

    watch = root.where(filter=FieldFilter("group", "==", "even")).on_snapshot(cb)
    time.sleep(1.5)
    root.document("q8").set({"i": 8, "group": "even"})
    ok = done.wait(8)
    watch.unsubscribe()
    assert ok, f"no update delivered (callbacks={seen})"
    return f"callbacks={seen}"


if out_path:
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)
passed = sum(v.startswith("PASS") for v in results.values())
print(f"[{label}] {passed}/{len(results)} passed")
sys.exit(0 if passed == len(results) else 1)
