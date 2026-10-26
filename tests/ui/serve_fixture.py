"""Disposable local console fixture with real permission and payment state."""
import sys

import uvicorn

from scoutbankai.api import create_app
from scoutbankai.bootstrap import initialize, sample_authority, submit_sample

directory, port = sys.argv[1], int(sys.argv[2])
settings, service, credentials = initialize(directory, f"http://127.0.0.1:{port}")
authority = sample_authority(service, credentials)
submit_sample(service, authority, 5000)
submit_sample(service, authority, 25000)
uvicorn.run(create_app(settings, service), host="127.0.0.1", port=port, access_log=False, log_level="error")
