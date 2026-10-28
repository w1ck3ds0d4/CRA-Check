# Official Apify Python base image, pinned by digest (python 3.13, published 2026-10-26).
# Bump the digest on purpose after checking the new image; never track a moving tag.
FROM apify/actor-python:3.13@sha256:134b21518882ef053a9f7b1b17f5d5246efc026cd9ef9c2c69d0f7b7f723c56f

COPY apify_actor/requirements.txt ./apify_actor/requirements.txt
RUN python -m pip install --no-cache-dir -r apify_actor/requirements.txt

# The engine is one stdlib-only file; the Actor wrapper imports it, so there is one copy of the checks.
COPY cra_report.py ./
COPY apify_actor/ ./apify_actor/

CMD ["python", "-m", "apify_actor"]
