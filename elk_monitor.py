from elasticsearch import Elasticsearch
import requests
import json
from datetime import datetime, timedelta
import time
import urllib3
import pytz

# Disable TLS insecure warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Elasticsearch config
es = Elasticsearch(
    "https://ins-elk.ntl.co.th:9200",
    basic_auth=("admin", "P@ssw0rd"),
    verify_certs=False
)

# Slack Webhook
SLACK_WEBHOOK_URL = "https://hooks.slack.com/services/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"

# Monitor settings
INDEX_NAME = "ag-*-production-*"
REQUEST_PATH = "/Payment/v2/paymentconfirm"
CHECK_INTERVAL_SECONDS = 60

bangkok_tz = pytz.timezone('Asia/Bangkok')

def send_to_slack(message: str, trace_id: str, running_number: str = "-"):
    popup_text = f"🚨 Response : Payment Confirm 500\n*runningnumber : {running_number}*"

    # สร้าง URL สำหรับดู Log โดยใช้ TraceId
    elk_url = f"https://ins-elk.ntl.co.th:5601/app/discover#/?_g=(filters:!(),refreshInterval:(pause:!t,value:0),time:(from:now%2Fd,to:now%2Fd))&_a=(columns:!(fields.RequestPath,fields.RequestBody,fields.ResponseBody,fields.AgResponseCode),filters:!(),hideChart:!t,index:'42035420-1a6b-11ec-b7b6-cff4644ed5fe',interval:auto,query:(language:kuery,query:'%22{trace_id}%22'),sort:!(!('@timestamp',desc)))"

    payload = {
        "username": "AG-Notify-Prod",
        "icon_emoji": ":rotating_light:",
        "text": popup_text,
        "blocks": [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"{message}\n\n🔗 *ดู Log*: <{elk_url}|Click here to view logs in EKL>"
                }
            }
        ]
    }
    headers = {"Content-Type": "application/json"}
    try:
        response = requests.post(
            SLACK_WEBHOOK_URL,
            data=json.dumps(payload),
            headers=headers,
            verify=False
        )
        print(f"Slack response: {response.status_code} - Slack message sent.", flush=True)
    except Exception as e:
        print("Slack webhook failed:", e, flush=True)


def format_slack_message(req_body: dict, res_body: dict, trace_id: str) -> str:
    req = req_body or {}
    res = res_body or {}
    err = res.get("responseerror", {})

    # สร้าง URL สำหรับดู Log โดยใช้ TraceId
    elk_url = f"https://ins-elk.ntl.co.th:5601/app/discover#/?_g=(filters:!(),refreshInterval:(pause:!t,value:0),time:(from:now%2Fd,to:now%2Fd))&_a=(columns:!(fields.RequestPath,fields.RequestBody,fields.ResponseBody,fields.AgResponseCode),filters:!(),hideChart:!t,index:'42035420-1a6b-11ec-b7b6-cff4644ed5fe',interval:auto,query:(language:kuery,query:'%22{trace_id}%22'),sort:!(!('@timestamp',desc)))"

    message = (
        f"*🚨 Areegator-Notify: PAYMENTCONFIRM Error 🚨*\n"
        f"\n"
        f"📝 *Request Info:*\n"
        f'🔹 agentcode: {req.get("agentcode", "-")}\n'
        f'🔹 agentid: {req.get("agentid", "-")}\n'
        f'🔹 leaddetailid: {req.get("leaddetailid", "-")}\n'
        f'🔹 period: {req.get("period", "-")}\n'
        f'🔹 verifyrunningnumber: {req.get("verifyrunningnumber", "-")}\n'
        f'🔹 runningnumber: {req.get("runningnumber", "-")}\n'
        f'🔹 flagCommission: {req.get("flagcommission", "-")}\n'
        f'🔹 empid: {req.get("empid", "-")}\n'
        f"\n"
        f"❌ *Response Error:*\n"
        f'🔥 errorcode: {err.get("errorcode", "-")}\n'
        f'📛 headermessage: {json.dumps(err.get("headermessage", None))}\n'
        f'💬 errormessage: {err.get("errormessage", "-")}\n'
        f'🆔 TraceId: {trace_id}\n'
        f"\n"
        f"🔗 *ดู Log*: <{elk_url}|Click here to view logs in EKL>\n"
        f'━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━'
    )
    return message


def check_logs():
    now = datetime.now(bangkok_tz)
    past = now - timedelta(seconds=CHECK_INTERVAL_SECONDS)
    query = {
        "bool": {
            "must": [
                {"match": {"fields.RequestPath": REQUEST_PATH}},
                {"match": {"fields.AgResponseCode": "500"}},
                {"range": {
                    "@timestamp": {
                        "gte": past.isoformat(),
                        "lte": now.isoformat()
                    }
                }}
            ]
        }
    }

    try:
        result = es.search(index=INDEX_NAME, size=10, query=query, sort=[{"@timestamp": "desc"}])
        hits = result["hits"]["hits"]

        if hits:
            for hit in hits:
                fields = hit["_source"].get("fields", {})
                req_body = fields.get("RequestBody", {})
                res_body = fields.get("ResponseBody", {})
                trace_id = fields.get("TraceId", "-")

                # Parse JSON strings
                if isinstance(req_body, str):
                    try:
                        req_body = json.loads(req_body)
                    except:
                        req_body = {}

                if isinstance(res_body, str):
                    try:
                        res_body = json.loads(res_body)
                    except:
                        res_body = {}

                slack_msg = format_slack_message(req_body, res_body, trace_id)
                running_number = req_body.get("runningnumber", "-")
                send_to_slack(slack_msg, trace_id, running_number)
                print(now.isoformat(timespec='seconds') + " - Slack alert sent.", flush=True)
        else:
            print(now.isoformat(timespec='seconds') + " - No error 500 found", flush=True)
    except Exception as e:
        print(now.isoformat(timespec='seconds') + " - ERROR: " + str(e), flush=True)


if __name__ == "__main__":
    print("Log monitoring started...", flush=True)
    while True:
        check_logs()
        time.sleep(CHECK_INTERVAL_SECONDS)
