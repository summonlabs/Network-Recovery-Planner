# Concurrency and ownership audit

Scope: every lock, thread, callback and owned handle in the runtime. The audit was
performed by reading the call paths, not only by running tests. Findings are listed
with the fix that landed.

## Lock inventory

| Lock | Owner | Guarded state | Held while |
| --- | --- | --- | --- |
| `SessionRegistry::mutex_` | `SessionRegistry` | session table, high water mark, next id | table lookup/update only |
| `PlannerService::Impl::queue_mutex` | `PlannerService` | work queue, `stopping`, queue high water | enqueue/dequeue and shutdown drain |
| `PlannerService::Impl::durable_mutex` | `PlannerService` | `DurableStore` (not thread safe by itself) | store append/snapshot |
| `JobState::mutex` | submitting thread and worker | job status, result, done flag | result hand-off only |
| `PlanningServer::Impl::connections_mutex` | `PlanningServer` | connection socket list | accept registration and shutdown sweep |

There is no lock hierarchy in which one of these is taken while another is held:
planning and store access happen strictly after the queue lock is released, and the
session registry is never entered from inside the store or the queue.

## Callback and notification discipline

* `PlanningService::submit_plan` callbacks are invoked from the worker with **no**
  internal lock held (`Impl::complete`).
* Condition variable notifications happen after the guard is released, or on a
  distinct `JobState` mutex that no other path needs.
* A callback may call back into the service (for example `plan()`); the
  concurrency suite exercises nested submission from a callback path.

## Findings and fixes

1. **Arena reference invalidation (fixed).** The plan search kept
   `const Node& current = arena_[i]` and then grew the arena with
   `std::vector::push_back`, invalidating the reference. AddressSanitizer
   reported a heap-use-after-free. The arena is now a `std::deque`, whose
   references stay valid when it grows, and the comment in the code states why.

2. **Use of a not-yet-inserted arena index (fixed).** When a generated state was
   already known, its tie-break encoding was read through
   `encoding_of(child_index)` *before* the child was inserted, reading one past
   the end of the arena. The child encoding is now derived from its parent. This
   was found by the MSVC debug STL bounds check (the process aborted with no
   output) and confirmed by the Release access violation.

3. **Iterating a container that is appended to during iteration (fixed).** The
   store's restart fencing pass iterated `records_` by reference while
   `record_fence()` appended to the same vector. The candidates are now copied
   out first.

4. **Whole-container re-entry under a lock (checked, not present).** Store
   operations are called only from `append_durable`, which holds only
   `durable_mutex`; no store call re-enters the service.

5. **Joining workers while holding state they need (checked, not present).**
   `shutdown()` swaps the queue under the queue lock, releases it, completes the
   drained jobs, and only then joins. Workers never need `durable_mutex` to
   observe the stop flag, so a join cannot deadlock against a worker holding the
   store lock.

6. **Read-lock then write-lock re-entry (checked, not present).** No type in the
   runtime takes a second lock of the same object; there is no `shared_mutex` in
   the codebase, so read-to-write upgrade hazards do not exist.

7. **Cross-object mutex order inversion (checked, not present).** The only nested
   acquisition is a job's `JobState::mutex` taken after the queue lock has been
   released. Jobs are never moved between locks while held.

8. **Moved-from handle ownership (fixed).** `transport::Socket` move construction
   and assignment set the source handle to `INVALID_SOCKET`, so a moved-from
   socket never double-closes. `Socket::close()` is idempotent and safe on an
   invalid handle; the concurrency suite asserts it.

9. **Close/shutdown races (checked, hardened).** `PlanningServer::shutdown()`
   marks `stopping` with `exchange`, shuts down the listener and every
   connection socket, joins the accept thread and the connection threads, and is
   idempotent. The connection thread erases its own socket from the registry under
   `connections_mutex`; the shutdown sweep copies nothing, it only calls
   `shutdown_both()` on shared pointers, so a concurrently erased entry cannot be
   dereferenced after free.

10. **Callbacks retaining references to mutable state (checked, not present).**
    Callbacks receive a value (`Result<PlanningResult>`); no lock-protected
    container reference escapes any API.

11. **Blocked socket teardown (fixed in tests, documented in the protocol).** A
    truncated frame leaves the server waiting for the remainder on that one
    connection; it never affects other sessions because each connection is served
    by its own thread, and `shutdown()` releases the read. The multiprocess suite
    was hanging on exactly this behaviour and now closes the client instead of
    waiting for a reply that the protocol never promises.

## Blocking operations

Every blocking call is released by shutdown or by the peer closing:

* `Socket::recv_some` returns once `shutdown_both()` is called on that socket,
  which is what `PlanningServer::shutdown()` does for every live connection;
* `::accept` returns once the listening socket is shut down and closed;
* `PlannerService::plan()` waits on a per-job condition variable that shutdown
  always signals, because drained jobs are completed with a `CLOSED` status.

The concurrency and multiprocess suites assert these releases directly rather than
sleeping and hoping.
