#!/bin/bash
export HEARTBEAT_FILE="/tmp/inrbot_heartbeat"
export LOG_SMTP="True"
/data/project/inaturalistreviewer/iNaturalistReviewer/venv/bin/python3 /data/project/inaturalistreviewer/iNaturalistReviewer/src/inrbot.py --auto
