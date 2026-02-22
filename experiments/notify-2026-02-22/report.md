# Notification Payloads — Security Alert

> Generated: 2026-02-22T15:29:19.368Z
> Mode: diff-notify (new issues only)
> Data source: Mock data

## Summary

| Metric | Count |
|--------|-------|
| Total alertable issues | 2 |
| 🔴 Critical | 1 |
| 🟠 High | 1 |
| Apps affected | 1 |
| Auto-fixable | 1 |
| Resolved since last scan | 2 |

## Per-App Breakdown

| App | Critical | High | Total | Auto-Fix |
|-----|----------|------|-------|----------|
| ShopEasy | 1 | 1 | 2 | 1 |

## Issue List

| # | Severity | Title | App | Source | Auto-Fix |
|---|----------|-------|-----|--------|----------|
| 1 | 🟠 High | Hardcoded API Key in AppDelegate.swift | ShopEasy | SecretDetection | — |
| 2 | 🔴 Critical | React Native Hermes Engine RCE (CVE-2024-1234) | ShopEasy | SCA | ✅ |

## Resolved Issues

2 issue(s) from the previous scan are no longer present.
IDs: ISS-009, ISS-010

## Slack Payload

```json
{
  "blocks": [
    {
      "type": "header",
      "text": {
        "type": "plain_text",
        "text": "🚨 2 New Security Issues Detected",
        "emoji": true
      }
    },
    {
      "type": "section",
      "text": {
        "type": "mrkdwn",
        "text": "*🔴 Critical:* 1\n*🟠 High:* 1\n*Apps affected:* 1\n*Scan time:* 2026-02-22T15:29:19.368Z"
      }
    },
    {
      "type": "divider"
    },
    {
      "type": "section",
      "text": {
        "type": "mrkdwn",
        "text": "🟠 *Hardcoded API Key in AppDelegate.swift*\n_App:_ ShopEasy · _Source:_ SecretDetection · _Category:_ Secret Detection"
      }
    },
    {
      "type": "section",
      "text": {
        "type": "mrkdwn",
        "text": "🔴 *React Native Hermes Engine RCE (CVE-2024-1234)*\n_App:_ ShopEasy · _Source:_ SCA · _Category:_ Vulnerability\n✅ Auto-fix available"
      }
    },
    {
      "type": "divider"
    },
    {
      "type": "section",
      "text": {
        "type": "mrkdwn",
        "text": "*Per-App Breakdown:*\n• *ShopEasy*: 🔴 1 Critical, 🟠 1 High"
      }
    },
    {
      "type": "section",
      "text": {
        "type": "mrkdwn",
        "text": "✅ *2 issues resolved* since last scan"
      }
    },
    {
      "type": "context",
      "elements": [
        {
          "type": "mrkdwn",
          "text": "📊 Ox Security Scan · 2026-02-22T15:29:19.368Z"
        }
      ]
    }
  ]
}
```

## Teams Payload (Adaptive Card)

```json
{
  "type": "message",
  "attachments": [
    {
      "contentType": "application/vnd.microsoft.card.adaptive",
      "content": {
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "type": "AdaptiveCard",
        "version": "1.4",
        "body": [
          {
            "type": "TextBlock",
            "text": "🚨 2 New Security Issues Detected",
            "weight": "bolder",
            "size": "large",
            "wrap": true,
            "color": "attention"
          },
          {
            "type": "FactSet",
            "facts": [
              {
                "title": "🔴 Critical",
                "value": "1"
              },
              {
                "title": "🟠 High",
                "value": "1"
              },
              {
                "title": "Apps Affected",
                "value": "1"
              },
              {
                "title": "Scan Time",
                "value": "2026-02-22T15:29:19.368Z"
              }
            ]
          },
          {
            "type": "TextBlock",
            "text": "---",
            "separator": true
          },
          {
            "type": "TextBlock",
            "text": "Top Issues",
            "weight": "bolder",
            "size": "medium"
          },
          {
            "type": "TextBlock",
            "wrap": true,
            "text": "🟠 **Hardcoded API Key in AppDelegate.swift**\n_ShopEasy_ · SecretDetection · Secret Detection"
          },
          {
            "type": "TextBlock",
            "wrap": true,
            "text": "🔴 **React Native Hermes Engine RCE (CVE-2024-1234)** ✅\n_ShopEasy_ · SCA · Vulnerability"
          },
          {
            "type": "TextBlock",
            "text": "---",
            "separator": true
          },
          {
            "type": "TextBlock",
            "text": "Per-App Breakdown",
            "weight": "bolder",
            "size": "medium"
          },
          {
            "type": "TextBlock",
            "text": "**ShopEasy**: 🔴 1 Critical, 🟠 1 High",
            "wrap": true
          },
          {
            "type": "TextBlock",
            "text": "✅ **2 issues resolved** since last scan",
            "color": "good",
            "wrap": true
          }
        ],
        "actions": [
          {
            "type": "Action.OpenUrl",
            "title": "Open Ox Security Dashboard",
            "url": "https://app.ox.security"
          }
        ]
      }
    }
  ]
}
```

## Integration Guide

### Slack Setup

1. Create a Slack app at https://api.slack.com/apps
2. Enable Incoming Webhooks and create one for your channel
3. Run:
```bash
OX_DRY_RUN=false OX_SLACK_WEBHOOK=https://hooks.slack.com/services/T.../B.../xxx \
  node scripts/notify.js send
```

### Microsoft Teams Setup

1. In Teams, go to channel > Connectors > Incoming Webhook
2. Configure the webhook and copy the URL
3. Run:
```bash
OX_DRY_RUN=false OX_TEAMS_WEBHOOK=https://outlook.office.com/webhook/... \
  node scripts/notify.js send
```

### CI/CD Integration (GitHub Actions)

```yaml
- name: Notify on new critical issues
  run: node scripts/notify.js send
  env:
    OX_API_KEY: ${{ secrets.OX_API_KEY }}
    OX_SLACK_WEBHOOK: ${{ secrets.SLACK_WEBHOOK }}
    OX_SEVERITY: Critical
    OX_DRY_RUN: "false"
```

### Diff-Notify Mode (Alert on Changes Only)

```bash
# Save a baseline snapshot
node scripts/notify.js generate
# Later, compare against it
OX_SNAPSHOT=experiments/notify-YYYY-MM-DD/snapshot.json node scripts/notify.js diff-notify
```
