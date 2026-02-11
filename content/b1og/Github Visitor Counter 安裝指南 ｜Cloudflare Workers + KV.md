---
title: "Github Visitor Counter 安裝指南 ｜Cloudflare Workers + KV"
date: 2025-10-29
author: "CHW"
tags:
  - infra
description: "使用 Cloudflare Workers + KV 產生可嵌入 GitHub Profile/README 的動態 SVG 訪客計數器。
內含 6 位數前置自動補零、外觀參數計數器，以及透過 GitHub Actions 因應 GitHub Camo 圖片快取的作法。..."
---

# Github Visitor Counter 安裝指南 ｜Cloudflare Workers + KV

使用 Cloudflare Workers + KV 產生可嵌入 GitHub Profile/README 的動態 SVG 訪客計數器。
內含 6 位數前置自動補零、外觀參數計數器，以及透過 GitHub Actions 因應 GitHub Camo 圖片快取的作法。

>[!Note]
> KV free tier 1,000 writes/day.

- English Version: [Github-Counter Installation Guide｜Cloudflare Workers + KV](https://hackmd.io/@CHW/r19bRRVRxg)
---

## Table of Contents

[TOC]

## PoC Preview
>[!Important]
Github: [Chw41/Visitor-Counter](https://github.com/Chw41/Github-Visitor-Counter)

將 `<WORKER_NAME>.<SUBDOMAIN>` 改成你的 Worker 網域。
範例（CHW）：chw-counter.chw41.workers.dev
```md
<p align="center">
  <img src="https://<WORKER_NAME>.<SUBDOMAIN>.workers.dev/?id=Chw41&min=6&color=39ff14&bg=000000&size=42&gap=6&radius=6&v=0000" alt="visitor count"/>
</p>
```
![image](https://hackmd.io/_uploads/Sy0FCC40ll.png)


## 安裝設定 (Cloudflare UI)
### 1. 建立 Worker
- 造訪 https://dash.cloudflare.com
- 側欄 Compute (Workers) → Workers → Create → 選 Worker，命名（e.g., chw-counter）→ Deploy
- 首次使用會要求設定 `*.workers.dev` 子網域

### 2. 建立 KV namespace
- 側欄 Storage & Databases → KV → Create namespace (e.g., chw-counter)

### 3. 將 KV 綁到 Worker
- 進入你的 Worker → Bindings 分頁 → Add binding
  - Type: KV Namespace
  - Namespace: 選擇第 2 步建立的 KV
  - Variable name: COUNTER → Add

### 4. 貼上 Worker 程式碼
- 前往 Source / Quick edit，以下述程式替換預設碼：\
完整程式可見 [/worker.js](https://github.com/Chw41/Github-Counter/blob/main/worker.js)
```js=
export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    try {
      if (url.pathname.startsWith("/admin/")) {
        if (req.method !== "POST" && req.method !== "GET")
          return new Response("Method Not Allowed", { status: 405 });

        const auth = req.headers.get("Authorization") || "";
        if (auth !== `Bearer ${env.ADMIN_TOKEN}`)
          return new Response("Unauthorized", { status: 401 });

        const id = url.searchParams.get("id") || "{User ID}"; // UserID
        const key = `count:${id}`;
        ...
```
將 `{User ID}` 改成你的使用者 ID。

## Outcomes
- 預覽（不增加計數）:
`https://<WORKER_NAME>.<SUBDOMAIN>.workers.dev/?id={User ID}&min=6&preview=1`

- 正式（會增加計數）:
`https://<WORKER_NAME>.<SUBDOMAIN>.workers.dev/?id={User ID}&min=6`

首次正式載入後，KV 會出現類似 `count:Chw41` 的 key。

## GitHub Actions
建立 `.github/workflows/bump-counter.yml`\
完整程式可見 [counter.yml](https://github.com/Chw41/Github-Counter/blob/main/counter.yml)
```yaml=
name: Bump counter cache key
on:
  schedule:
    - cron: "*/30 * * * *"   # every 30 minutes (UTC)
  workflow_dispatch:

permissions:
  contents: write

jobs:
  bump:
    runs-on: ubuntu-latest
    ...
```
說明：GitHub 會透過 Camo 快取圖片。定期變更 `v` 參數可使快取失效，讓 GitHub 重新回源抓圖，達到至少每 30 分鐘增加一次計數的效果。

## 嵌入至 README
```
<div align="center" style="pointer-events: none;">
  <img src="https://<WORKER_NAME>.<SUBDOMAIN>.workers.dev/?id={User ID}&min=6&color=39ff14&bg=000000&size=42&gap=6&radius=6&v=0000" alt="visitor count"/>
</div>
```
> `id`: 計數鍵（相同鍵共用同一數值；可使用不同鍵建立多個計數器）\
`min=6`: 至少顯示 6 位數並自動補零\
`Style`: 文字顏色, 文字背景, 編框尺寸, 間距, 圓角\
`v`: 快取破壞參數；修改其值即可強迫 GitHub 重新抓圖

## 嵌入完成 ✅
![image](https://hackmd.io/_uploads/Sy0FCC40ll.png)

###### tags: `github` `visitor` `counter` `Cloudflare`
