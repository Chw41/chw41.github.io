---
title: "Github Visitor Counter Installation Guide｜Cloudflare Workers + KV"
date: 2025-10-21
author: "CHW"
tags:
  - infra
description: "Generate a dynamic SVG visitor counter using Cloudflare Workers + KV, embeddable in your GitHub Profile/README.
Includes 6-digit zero-padding, style params, and a GitHub Camo cache workaround via GitHub Actions..."
---

# Github Visitor Counter Installation Guide｜Cloudflare Workers + KV

Generate a dynamic SVG visitor counter using Cloudflare Workers + KV, embeddable in your GitHub Profile/README.\
Includes 6-digit zero-padding, style params, and a GitHub Camo cache workaround via GitHub Actions.

>[!Note]
> KV free tier 1,000 writes/day.

- 繁體中文安裝教學: [Github-Counter 安裝指南 ｜Cloudflare Workers + KV](https://hackmd.io/@CHW/HJ4uWyB0xx)
---

## Table of Contents

[TOC]

## PoC Preview
>[!Important]
Github: [Chw41/Visitor-Counter](https://github.com/Chw41/Github-Visitor-Counter)

Replace `<WORKER_NAME>.<SUBDOMAIN>` with your Worker domain.\
Example for CHW: chw-counter.chw41.workers.dev.
```md
<p align="center">
  <img src="https://<WORKER_NAME>.<SUBDOMAIN>.workers.dev/?id=Chw41&min=6&color=39ff14&bg=000000&size=42&gap=6&radius=6&v=0000" alt="visitor count"/>
</p>
```
![image](https://hackmd.io/_uploads/Sy0FCC40ll.png)


## Setup (Cloudflare UI)
### 1. Create a Worker
- Visit https://dash.cloudflare.com
- Left sidebar Compute (Workers) → Workers → Create → choose Worker, name it (e.g., chw-counter) → Deploy
- First-time users will be asked to set a *.workers.dev subdomain (one-time)

### 2. Create a KV namespace
- Left sidebar Storage & Databases → KV → Create namespace (e.g., chw-counter)

### 3. Bind KV to the Worker
- Open your Worker → Bindings tab → Add binding
  - Type: KV Namespace
  - Namespace: select the KV from step 2
  - Variable name: COUNTER → Add

### 4. Paste the Worker code
- Go to Source / Quick edit, replace the default code with:\
The code can be found in [/worker.js](https://github.com/Chw41/Github-Counter/blob/main/worker.js)
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
Change `{User ID}` to your User ID.

## Outcomes
- Preview (no increment):
`https://<WORKER_NAME>.<SUBDOMAIN>.workers.dev/?id={User ID}&min=6&preview=1`

- Live (increments):
`https://<WORKER_NAME>.<SUBDOMAIN>.workers.dev/?id={User ID}&min=6`

After the first live hit, KV will show a key like count:Chw41.

## GitHub Actions
Create `.github/workflows/bump-counter.yml`\
The code can be found in [counter.yml](https://github.com/Chw41/Github-Counter/blob/main/counter.yml)
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
GitHub’s Camo caches images. Changing the v parameter invalidates the cache, causing GitHub to re-fetch the image, resulting in at least one counter increment every 30 minutes.

## Embed into README
```
<div align="center" style="pointer-events: none;">
  <img src="https://<WORKER_NAME>.<SUBDOMAIN>.workers.dev/?id={User ID}&min=6&color=39ff14&bg=000000&size=42&gap=6&radius=6&v=0000" alt="visitor count"/>
</div>
```
> `id`: counter key (same key or use different keys for multiple counters)\
`min=6`: show at least 6 digits\
`Style`: color, background, box size, gap, radius\
`v`: cache buster only; change its value to force GitHub to re-fetch the image

## Embeded complete ✅
![image](https://hackmd.io/_uploads/Sy0FCC40ll.png)