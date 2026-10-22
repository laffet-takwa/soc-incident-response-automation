"""Optional Slack and Telegram summaries; credentials remain environment-only."""

from __future__ import annotations

import logging

import requests

log = logging.getLogger(__name__)


class Notifier:
    def __init__(self, settings, session=None):
        self.settings = settings
        self.session = session or requests.Session()

    def send(self, alert_id: str, title: str, score: dict, thehive: dict) -> dict:
        score_text = "unscored" if score.get("score") is None else f"{score['score']}/100"
        hive_link = thehive.get("url", "")
        text = (
            f"SOC lab alert {alert_id}\n{title[:300]}\nRisk: {score_text}\n"
            f"TheHive: {hive_link}\nApproval required before response."
        )
        results = {}
        if self.settings.slack_webhook_url:
            # Block Kit callbacks must target the authenticated approval endpoint.
            payload = {
                "text": text,
                "blocks": [
                    {"type": "section", "text": {"type": "mrkdwn", "text": text}},
                    {
                        "type": "actions",
                        "elements": [
                            {
                                "type": "button",
                                "text": {"type": "plain_text", "text": "Approve"},
                                "style": "primary",
                                "value": alert_id,
                                "action_id": "approve",
                            },
                            {
                                "type": "button",
                                "text": {"type": "plain_text", "text": "Reject"},
                                "style": "danger",
                                "value": alert_id,
                                "action_id": "reject",
                            },
                        ],
                    },
                ],
            }
            results["slack"] = self._post(self.settings.slack_webhook_url, payload)
        if self.settings.telegram_bot_token and self.settings.telegram_chat_id:
            url = f"https://api.telegram.org/bot{self.settings.telegram_bot_token}/sendMessage"
            payload = {
                "chat_id": self.settings.telegram_chat_id,
                "text": text,
                "reply_markup": {
                    "inline_keyboard": [
                        [
                            {"text": "Approve", "callback_data": f"approve:{alert_id}"},
                            {"text": "Reject", "callback_data": f"reject:{alert_id}"},
                        ]
                    ]
                },
            }
            results["telegram"] = self._post(url, payload)
        return results or {"status": "disabled"}

    def _post(self, url: str, payload: dict) -> dict:
        try:
            response = self.session.post(url, json=payload, timeout=self.settings.request_timeout)
            response.raise_for_status()
            return {"status": "ok"}
        except requests.RequestException as exc:
            log.warning("Notification delivery failed: %s", type(exc).__name__)
            return {"status": "error", "error": type(exc).__name__}

    def answer_telegram_callback(self, callback_id: str, text: str) -> None:
        if not self.settings.telegram_bot_token:
            return
        url = f"https://api.telegram.org/bot{self.settings.telegram_bot_token}/answerCallbackQuery"
        self._post(url, {"callback_query_id": callback_id, "text": text[:180]})
