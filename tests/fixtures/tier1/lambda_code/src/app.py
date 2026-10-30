import os

TABLE = os.environ.get("TABLE", "orders")
GH_TOKEN = "{{CANARY:lambdacode}}"


def handler(event, context):
    return {"ok": True}
