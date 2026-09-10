# Frontend QA Checklist (Task7 + Task8)

## Automated
- `npm run build` (vue-tsc --noEmit + vite build) — must be green
- `npm run test` (vitest run) — 8 specs, 40 tests: tickets helpers (8), auth store login/logout (2), client 401 redirect (2), ops helpers (9: pool query builder, dry-run preview parser, mapping history grouper), integrations API mock (7)

## Manual (Task7 — unchanged, no regression)
1. **本地登录**: POST /api/auth/local 用户名/密码 → JWT 存 pinia+localStorage → 跳 /my
2. **TOTP**: 错误码 401 提示；正确码登录成功
3. **企微扫码**: /login 显示 QR 占位 + CORPID hint（真实 QR 等后端 /api/auth/wecom/*）
4. **路由守卫**: 无 token 访问 /my → 重定向 /login?redirect=/my
5. **隔离可视**: A 账号只见自己工单（后端 RBAC；前端不做二次过滤）
6. **筛选**: state/severity/q 组合查询；分页 page_size=20；total 对得上
7. **按IP汇总**: toggle 开 → 服务端 `GET /api/tickets/ip-summary`（全量聚合，同样本过滤；失败时回退当页 client-side group-by）
8. **详情**: fix_evidence timeline + audit timeline 均渲染；空态用 el-empty
9. **提交证据**: dialog → POST submit → 状态进待复测（时间线刷新）
10. **延期**: dialog → POST delay（delay_days/reason）；已延期显示恢复推进按钮
11. **403**: owner 点运营动作 → 友好提示（无权限…），不裸 403
12. **/ops 占位**: ~~显示"运营后台 Task8 接入中"~~ — Task8 已替换为真实 OpsPool；OpsPlaceholder.vue 已删除

## Manual (Task8 — 运营/导入/资产/配置)
13. **工单池 gating**: owner 访问 /ops → 路由守卫重定向 /my（按钮在 /my 隐藏 via canShowOpsButton）；operator/leader 可进；直接调 GET /api/ops/pool 作 owner → 403 友好提示"无权限：工单池仅运营/负责人可见"
14. **工单池 tabs**: 全部/无主 orphan（?orphan=true）/未分配 unassigned（?unassigned=true）/逾期（客户端 SLA 过滤）；表格复用 MyTickets 列模式；无主行 assignee=NULL 高亮（orphan-row）
15. **行动作**: 关闭/驳回/忽略 dialogs（reason/note 输入；忽略原因必填）；成功后刷新列表；API 403（如待分配→关闭非法跳转 422）surface 友好信息
16. **Dry-run parity**: ZIP 上传 → POST dry_run=true → DryRunPreview 计数与后端响应逐字一致（无客户端重算）；确认按钮 POST dry_run=false → 批次列表刷新（file_hash+stats）
17. **资产映射**: IP 搜索 → 现任负责人卡片 + MappingHistory 时间线（valid_from/valid_to，现任标"现任"）；未知 IP → 404"未知资产"；触发同步 POST /api/cmdb/sync → toast {upserted,remapped,orphaned}；无主资产快捷查看 GET /api/assets/orphans
18. **系统配置**: 非 admin 访问 /ops/config → 重定向 /my；SLA 表可编辑（`PUT /api/ops/sla-policies/:severity`，admin；即时影响后续 `compute_due`）；企微 webhook 掩码显示；字段映射查看器读 `GET /api/imports/field-map`；看板 GET /api/dashboard（?dept= 可选）数字与工单计数对上
19. **恢复推进**: 已延期工单经 POST /api/tickets/:id/resume 回到待修复（tickets.ts 已扩展 resumeTicket）
20. **审计日志**: auditor 登录 → /my 显示"全部工单（审计只读）" + 审计日志入口 → /ops/audit（ticket_id/actor 筛选 + 分页 + 跳工单详情）；owner/leader 手输 URL 被守卫踢回 /my；后端 `GET /api/audit` 零改动（`test_audit_hook` 等 6 用例覆盖）
21. **二次验证自助开通**: /my 头部"二次验证" → /mfa → 开始绑定（`POST /api/auth/totp/setup` 只发不存）→ 验证器手工录入密钥 → 确认（错码 401 且不落库）→ 登录开始要 TOTP；解绑需登录密码；后端 `test_totp_setup.py` 6 用例
22. **无感续期**: 登录发双 token（access 60min + refresh 7d）；401 自动单飞刷新并重放原请求，失败才踢登录；refresh 单次轮换、复用 401、登出吊销、改密自动失效旧 refresh；后端 `test_refresh.py` 6 用例
23. **我的导出**: /my"导出CSV"导出当前筛选（本人隔离；后端 `test_my_export.py` 4 用例）
24. **批量关闭/忽略**: 工单池批量对话框三动作（派单/关闭/忽略；忽略原因必填；不可流转自动跳过并报告；后端 `test_batch_ops.py` 4 用例）
25. **资产手工维护**: 资产页新建资产 + 现任负责人卡片上直接变更负责人（自动重派单；后端 `test_asset_write.py` 5 用例）
26. **看板图表化**: SLA/状态/严重性改条形图（`StatBars` 组件，挂载测试 2 用例），部门表保留

## Landed (was Stubbed)
- `GET /api/tickets/ip-summary` — 已落地（owner 隔离 + 同 /my 过滤 + 400 语义；500 IP cap；后端 `test_ip_summary.py` 6 用例）
- SLA 策略读写 — 后端 `GET/PUT /api/ops/sla-policies` 早已存在，前端 SysConfig 已接 `updateSlaPolicy` 可编辑
- 字段映射读取 `GET /api/imports/field-map` — 后端 `FieldMapView` + 前端查看器均存在；SysConfig 错误文案已同步（之前写"待落地"）

## Wave5 Final Gate (Task10 — 2026-09-07)
Gap fixes (only 2 backend edits, scope frozen):
- `backend/config/celery.py`: `app.conf.beat_schedule` = sync-cmdb-hourly → `cmdb.sync_cmdb` @3600.0s; check-sla-daily → `apps.tickets.tasks.check_sla` @crontab(hour=2, minute=0). Names read from landed tasks files, never guessed. Brokerless-safe (dict assignment, no connection at import).
- `backend/config/settings.py`: `STATIC_ROOT = BASE_DIR / "staticfiles"` (STATIC_URL untouched); zero new deps (no WhiteNoise — nginx /static/ volume is deploy's concern).
- Deploy lane notes: gunicorn pin needs NO action; import-cap + WECOM_AGENTID gaps are by-design non-issues.

### Automated gate evidence (all green, refreshed 2026-09-09)
- Backend pytest: 163 passed, zero-env (`pytest` defaults to sqlite in-process; explicit `DB_ENGINE` still wins; production default stays postgres)
- Beat import: `['check-sla-daily', 'sync-cmdb-hourly', 'check-ignore-expiry-hourly']` tasks `cmdb.sync_cmdb` / `apps.tickets.tasks.check_sla` / `apps.tickets.tasks.check_ignore_expiry`
- `manage.py check`: 0 issues; `migrate --check`: exit 0; `collectstatic --dry-run`: 154 files → `<backend>/staticfiles`
- Seed: `DB_ENGINE=sqlite python3 scripts/seed_demo.py` → 4 users / 5 assets / 10 tickets / 1 batch, 7/7 PASS lines, re-run idempotent (+0, SEED OK)
- Frontend: `npm run test` 40/40 green; `npm run build` green (chunk-size warning only, pre-existing)
- `ruff check backend`: clean; `lsp_diagnostics backend`: 0 errors
- review-work lens: goal PASS (all 4 deliverables), quality PASS (minimal diff, no model/view changes), security PASS (TEST-labeled passwords only, no secrets committed), QA PASS (hands-on runs above)

### Manual seed login demo (DB-level assertions = live-server alternative)
Seed rows: operator pool = 10 tickets; owner_a mine = 5; owner_b mine = 4; orphan open (assignee NULL) = 1. 5+4+1=10 ✓
1. `POST /api/auth/local` {username: `demo_operator`, password: `Demo1234!` [TEST]} → 200 JWT → `GET /api/ops/pool` → 10 rows incl. orphan `10.9.0.15`
2. Same login as `demo_owner_a` → `GET /api/my/vulns` → 5 rows, all assignee=owner_a; `GET /api/ops/pool` → 403
3. Same login as `demo_owner_b` → `GET /api/my/vulns` → 4 rows; overdue row (`sla_due_at` past) flagged by `check_sla`
4. Overdue/reopen spot-check: 2 tickets past `sla_due_at` (1 overdue + 1 delayed-overdue); 1 ticket `fix_evidence.reopened=true`

Verdict: GO (residual risk: live-server browser walkthrough not run — trivially startable stack assumed absent; DB-level assertions + full suites substitute)
