# data/runtime_exposure.json

**Placeholder for real Netdata data**, per the Phase 6 plan (standing up
Netdata against all 4 apps is real infra work the plan itself flags as the
first thing to cut if time-constrained). Read by
[`graph_builder/runtime_exposure.py`](../backend/graph_builder/runtime_exposure.py).

Reasoning behind the values:

- `hackathon-starter` and `node-realworld` are the two pure public-facing
  web app/API apps -- higher `request_volume_normalized` and
  `resource_criticality`.
- `microblog` (Flask + RQ worker) and `flack` (Flask + Celery worker) each
  blend a background-task component into one Application node. They're
  still `internet_facing` (their web tier faces the internet), but scored
  lower on volume/criticality than the pure web apps -- not zero, since
  they do serve real traffic too.

All three fields are placeholders reasoned by hand, not measured. Swap this
file's values (or the whole read path in `runtime_exposure.py`) out for
real Netdata metrics later -- see that module's docstring.
