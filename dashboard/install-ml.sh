#!/usr/bin/env bash
# Optional local vision stack for --faces / --clip and the dashboard's visual panel.
# Isolated Python 3.12 venv under ml/ (the system 3.14 has no wheels for this stack yet);
# the models are downloaded once into ml/models/ so scans never fetch anything later.
set -euo pipefail
OSINT="$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)"
VENV="$OSINT/ml/.venv"
command -v uv >/dev/null || { echo "install uv first:  pip install --user uv"; exit 1; }
uv python install 3.12
[ -x "$VENV/bin/python" ] || uv venv --python 3.12 "$VENV"
# CPU torch first: pulled in later by open_clip it would come from PyPI as the multi-GB CUDA build.
# A CUDA build that is already present is kept; vision.py runs on the CPU either way.
if ! "$VENV/bin/python" -c "import torch" 2>/dev/null; then
  uv pip install --python "$VENV/bin/python" torch torchvision --index-url https://download.pytorch.org/whl/cpu
fi
uv pip install --python "$VENV/bin/python" \
  numpy pillow onnxruntime insightface opencv-python-headless open_clip_torch telethon
# Optional DeepFace confirmer: pulls TensorFlow (~2 GB) and keeps its weights in ~/.deepface.
# KARGU_SKIP_DEEPFACE=1 leaves it out; --faces and --clip work without it.
if [ "${KARGU_SKIP_DEEPFACE:-0}" != "1" ]; then
  uv pip install --python "$VENV/bin/python" deepface tf-keras retina-face
fi
echo "downloading the models ..."
"$VENV/bin/python" "$OSINT/ml/vision.py" warmup
echo "Done. InsightFace (--faces), the DeepFace confirmer (--deepface), CLIP (--clip)"
echo "and Telegram search are now available."
