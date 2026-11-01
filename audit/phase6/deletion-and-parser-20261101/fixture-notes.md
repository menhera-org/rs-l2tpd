# Fixture corrections before qualification

The first session-loss prototype inspected the asynchronous fake deletion
before settling it. The corrected fixture calls the fake kernel's tick and
asserts actual absence before injecting loss.

That prototype also expected the event monitor's resynchronization warning
while directly injecting L2TP loss. The two sources have distinct handling;
the final case checks L2TP recovery and preserved identity instead.

The first disabled-forwarding prototype left store capacity at zero. In that
state the runtime needs no withdrawal and the event wait did not complete.
The exploratory test was terminated. The final fixture announces capacity
before reconciliation, obtains a genuine pending request, and bounds the
event wait with Tokio's timeout. It then exercises the helper's no-store
answer and proves immediate cleanup.

These were fixture errors. No production behavior or specification changed.
The final formatted source passed all positive qualifications and the six
independent failure controls.
