# Official Apify Python base image, pinned by digest (python 3.13, published 2026-10-26).
# Bump the digest on purpose after checking the new image; never track a moving tag.
FROM apify/actor-python:3.14@sha256:8da4d45fdf043726d872639a6ba03bc38af2fc5e74703ca222cf4fb0955e2204

COPY apify_actor/requirements.txt ./apify_actor/requirements.txt
RUN python -m pip install --no-cache-dir -r apify_actor/requirements.txt

# The engine is one stdlib-only file; the Actor wrapper imports it, so there is one copy of the checks.
COPY cra_report.py ./
COPY apify_actor/ ./apify_actor/

CMD ["python", "-m", "apify_actor"]
