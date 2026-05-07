# ML Detection Harness — Makefile
#
# Workflow:
#   1. make setup          — install Python dependencies
#   2. Capture traffic     — use capture/run_capture.sh
#   3. make extract        — extract features from pcaps
#   4. make train          — train both classifiers
#   5. make evaluate       — run evaluation report
#   6. make all            — steps 3-5 in sequence

VENV     := .venv
PYTHON   := $(VENV)/bin/python3
PIP      := $(VENV)/bin/pip

REAL_DIR   := captures/real
GHOST_DIR  := captures/ghost
FEATURES   := features.csv
MODEL_XGB  := model_xgboost.joblib
MODEL_CNN  := model_cnn.pt
REPORT_XGB := report_xgboost.json
REPORT_CNN := report_cnn.json

.PHONY: setup extract train train-xgboost train-cnn evaluate clean all

setup:
	python3 -m venv $(VENV)
	$(PIP) install --upgrade pip
	$(PIP) install -r requirements.txt
	@echo "[+] Virtual environment ready at $(VENV)"

extract: $(FEATURES)

$(FEATURES): $(wildcard $(REAL_DIR)/*.pcap) $(wildcard $(GHOST_DIR)/*.pcap)
	$(PYTHON) features/extract.py \
		--real-dir $(REAL_DIR) \
		--ghost-dir $(GHOST_DIR) \
		-o $(FEATURES)

train: train-xgboost train-cnn

train-xgboost: $(FEATURES)
	$(PYTHON) classifier/train_xgboost.py \
		--features $(FEATURES) \
		--output $(MODEL_XGB) \
		--report $(REPORT_XGB)

train-cnn: $(FEATURES)
	$(PYTHON) classifier/train_cnn.py \
		--features $(FEATURES) \
		--output $(MODEL_CNN) \
		--report $(REPORT_CNN)

evaluate: $(MODEL_XGB) $(FEATURES)
	$(PYTHON) classifier/evaluate.py \
		--model $(MODEL_XGB) \
		--features $(FEATURES)

all: extract train evaluate

clean:
	rm -f $(FEATURES) $(MODEL_XGB) $(MODEL_CNN) $(REPORT_XGB) $(REPORT_CNN)
	rm -rf $(VENV) __pycache__ */__pycache__
