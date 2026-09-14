"""End-to-end TestHelper-based test. No PHP is ever executed -- the sample fixture
(test/samples/*.cart) is a small synthetic PHP file (not real malware) combining a
decode chain with a direct-taint sink.
"""
import os

import pytest
from assemblyline.common.importing import load_module_by_path
from assemblyline_service_utilities.testing.helper import TestHelper

os.environ["SERVICE_MANIFEST_PATH"] = os.path.join(os.path.dirname(__file__), "..", "service_manifest.yml")

RESULTS_FOLDER = os.path.join(os.path.dirname(__file__), "results")
SAMPLES_FOLDER = os.path.join(os.path.dirname(__file__), "samples")

service_class = load_module_by_path(
    "phpsim.phpsim.PhpSim", os.path.join(os.path.dirname(__file__), "..")
)
th = TestHelper(service_class, RESULTS_FOLDER, SAMPLES_FOLDER)


@pytest.mark.parametrize("sample", th.result_list())
def test_sample(sample):
    th.run_test_comparison(sample)
