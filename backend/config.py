import os

# --------------------------------------------------
# Model Version Configuration
# --------------------------------------------------
# Set MODEL_VERSION in your .env file or system environment:
#   MODEL_VERSION=IF_v2
# If not set, defaults to IF_v2

MODEL_VERSION = os.getenv("MODEL_VERSION", "IF_v2")
