# Draft controller interface — review before the pilot

This is a proposed interface for a fair experiment, not text quoted from the
supervisor's document. Freeze it and the behavior contract before generation.
Do not give future feature requirements to base-generation agents.

The harness launches one controller per case using `ryu-manager CONTROLLER.py`.
OpenFlow 1.3 listens on loopback port 6653; HTTP listens on loopback port 8080.
One switch has DPID 1. Hosts h1/h2/h3 initially use switch ports 1/2/3, MACs
00:00:00:00:00:01/02/03 and IPv4 addresses 10.0.0.1/2/3.

## Observability required at every stage

- `GET /rain/status` returns HTTP 200 and a JSON object:
  `{"switches":[1],"learned":{"1":{"00:00:00:00:00:01":1}},"blocked":[],"errors":[]}`.
  `learned` reports observations; it must not set the MAC table for the tests.
  The checker compares actual packet captures and switch flows as well.
- `POST /rain/sync` returns `{"complete":true}` only after BarrierReply for all
  connected switches, covering previously issued flow updates. No switch: 503.
  Protocol errors must not produce a successful completion response.
- No packet-generating activity occurs concurrently with a sync request. The
  movement case waits for the source observation before requesting sync.

## Change 1: destination blocklist

Read initial destination MACs from the JSON array in environment variable
`RAIN_BLOCKED`. Empty means allow all. Matching is exact MAC matching. ARP
broadcasts retain their broadcast destination and are not blocked merely
because their target IP belongs to a blocked MAC. A blocked source may send
to allowed destinations. A ping to/from a blocked host can still fail because
one leg of the round trip has a blocked destination.

## Change 2: host movement

After a Packet-In reveals the same source MAC on a new port, update its location
and invalidate stale forwarding rules. Existing destination policy still holds.
The first draft simulates movement by changing the host-facing OVS OpenFlow
port number to 4; the host's Linux interface, IP and MAC remain fixed. This
tests port relocation, not cable failure, multi-switch roaming or topology repair.

## Change 3: runtime updates

`PUT /rain/policy` with `{"blocked":["00:00:00:00:00:02"]}` replaces the entire
blocklist. `{"blocked":[]}` unblocks all. Return HTTP 200 and `{"complete":true}`
only after all policy-related flow changes are acknowledged by BarrierReply.
Reject malformed MACs, wrong types, missing keys and extra keys with HTTP 400
without changing policy. Timeout or OpenFlow errors cannot count as success.
These input-error requirements are draft choices to review with Soudeh.

The unchanged `ryu.app.example_switch_13` does not expose these endpoints.
Using it directly requires an observability adapter; do not interpret an API
startup error as a forwarding regression.
