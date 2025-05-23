# Automation Mass Config — MikroTik  
_A web-based bulk-configuration toolkit for RouterOS devices_

![Python](https://img.shields.io/badge/Python-3.11%2B-blue?logo=python)
![Django](https://img.shields.io/badge/Django-5.x-success?logo=django)
![License](https://img.shields.io/badge/License-MIT-lightgrey)

> Manage **hundreds** of MikroTik routers from a single dashboard – push commands, verify results, and keep an audit trail.

---

## ✨ Key Features

| Area | What you get |
|------|--------------|
| **Device onboarding** | CSV/Excel mass-import, per-device credential vault |
| **Bulk command runner** | Push RouterOS CLI snippets via **SSH** or the **API** (paramiko / routeros-api) |
| **Verification** | Compare running config against golden templates, view colored pass/fail table |
| **Logbook** | Every action is stored; download CSV for audit & SLA evidence |
| **Modern UI** | Responsive **Bootstrap 5** + dark mode toggle |
| **Container-ready** | `Dockerfile` + `docker-compose.yml` for one-command spin-up |
| **CI-friendly** | `Procfile` included (Heroku/Render/Fly.io) |
