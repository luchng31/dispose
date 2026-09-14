"""Task6 route contracts (stable for frontend lane Task7/Task8, zero new deps).

Tickets (owner-isolated via get_visible_tickets; 404 when not visible):
  GET  /api/tickets/my?state=&severity=&q= -> paginated list rows
       {id, ip, port, title, severity, state, sla_due_at, assignee, reopen_count}
       bad state/severity -> 400 {detail, allowed}; page_size default 20 max 100
  GET  /api/tickets/ip-summary?state=&severity=&q= -> {results:
       [{ip, total, overdue, severities{4}}]} per-IP rollup over the FULL
       filtered set (owner-isolated, same filters as /my; cap 500 IPs)
  GET  /api/tickets/my/export?state=&severity=&q= -> CSV (UTF-8 BOM, cap 10k)
       of my filtered tickets (owner-isolated; pool export stays ops-only)
  GET  /api/tickets/<id> -> detail row (all list fields + protocol, service,
       plugin_id, plugin_name, cve, cvss, description, solution, asset,
       first_seen_at, last_seen_at, fix_evidence, delay_until, ignore_reason,
       batch, created_at, updated_at, timeline[{id, action, actor, created_at,
       diff_json}] oldest-first, read-only)
  POST /api/tickets/<id>/submit {evidence} -> 待修复→待复测; illegal edge 422
  POST /api/tickets/<id>/delay {delay_until|delay_days, reason,
       co_approved_by?} -> 待修复→已延期 (approval inside transition());
       owner without approval 403, leader >30d without co-approval 403
   POST /api/tickets/<id>/resume {} -> 已延期→待修复 (delay ends, work resumes)
   POST /api/tickets/<id>/delay-request {delay_days|delay_until, reason} ->
        owner 申请延期 (待修复 only, 201); operator/leader 审批:
   GET  /api/ops/delay-requests?status= -> pending/approved/rejected list
   POST /api/ops/delay-requests/<id>/approve|reject {note?} -> 批准走
        transition 待修复→已延期 (leader ≤30d, 超过需运营)
   POST /api/ops/remind {ids[]} -> 手动提醒邮件 (IsOperator): 按负责人聚合
        成一封; fix_evidence.last_reminded_at 24h 冷却自动跳过并报告;
        无主/已关闭跳过; SMTP 未配置时 sent_emails=0 不标记可重试;
        每张已发工单写审计 ticket.remind; -> 200
        {requested, sent_emails, reminded_tickets, skipped_cooldown,
         skipped_unassigned}
    POST /api/tickets/<id>/attachments (multipart file=) -> 201
         {id, url, name, uploaded_by, created_at}; owner-isolated (else 404);
         images png/jpg/gif/webp only, 5MB max, magic-byte sniffed (else 400);
         stored under uuid-prefixed names, display name strips the prefix;
         auditor POST 403

Ops pool (operator/leader only; others 403):
   GET  /api/ops/pool?orphan=&unassigned=&state=&severity=&q= -> paginated list
         rows (unassigned: assignee NULL; orphan: unassigned 且 IP 无现任负责人
         映射；severity 可逗号多选，非法 400；q 模糊匹配 IP/插件名/插件ID/CVE；
         手工派单后同时退出两列，IP 缺口去资产管理补映射）
    GET  /api/ops/pool/export?<pool filters> -> CSV (UTF-8 BOM, cap 10k rows,
         operator/leader; formula cells prefixed with a single quote)
   POST /api/ops/batch-assign {ids[], assignee} -> batch dispatch (IsOperator,
        cap 500; assigned + skipped[{id, reason}]; summary mail, no per-ticket
        mail)
   POST /api/ops/batch-close {ids[], note?} -> batch close (IsOperator,
        cap 500; 待复测→已闭合 per ticket, others skipped[{id, reason}])
   POST /api/ops/batch-ignore {ids[], reason*} -> batch ignore (IsOperator,
        cap 500; reason required 422; illegal edges skipped[{id, reason}])
    GET  /api/ops/users -> {results[{id, username, dept, role}]} assignable
         users (active, non-auditor), operator/leader only
    GET  /api/ops/departments -> {first[], tree{一级:[二级...]}, count}
         级联筛选数据源（去重用户部门，operator/leader only）
    POST /api/ops/<id>/assign {assignee} -> manual dispatch (IsOperator);
         待分配→待修复, other open states reassigned in place (SLA untouched);
         closed/ignored -> 422, unknown/inactive user -> 404
    PATCH /api/ops/<id>/edit {title?, severity?, description?, solution?,
         cve?, cvss?, source?} -> content fix (IsOperator); ip/port immutable
         (400); closed/ignored -> 422; severity change recomputes SLA from
         first_seen; source switches to that MANUAL batch (empty keeps);
         every change audited (ticket.update); -> 200 detail
    DELETE /api/ops/<id> -> hard-delete ticket, any state (IsOperator,
         testing convenience); AuditLog ticket.delete row survives
         (ticket FK SET_NULL) with {ip,title,state,severity} snapshot;
         unknown -> 404; -> 200 {deleted, id, ...snapshot}
    POST /api/ops/tickets {ip*, port=443, protocol, severity*, title*, cve?,
         description?, solution?, cvss?, assignee?, source?} -> manual entry
         (IsOperator); omitted assignee auto-dispatches via IP owner map;
         assigned -> 待修复 with SLA clock, ownerless -> 待分配 orphan pool;
         来源 = 手填文本(复用同名手工批次)或默认"手工录入"; -> 201 detail
   GET  /api/ops/admin/users?q=&role=&active= -> user rows (IsOperator)
   POST /api/ops/admin/users {username*, dept, email, role, wecom_userid,
        password?} -> create (temp password returned once)
    PATCH /api/ops/admin/users/<username> {email, dept, wecom_userid, role,
         is_active} -> update profile (deactivating an admin needs admin role)
    POST /api/ops/admin/users/<username> {password?} -> reset password
         (temp returned once when absent; resetting an admin needs admin role)
    DELETE /api/ops/admin/users/<username> -> hard-delete user (IsOperator,
         testing convenience); their open tickets fall back to unassigned
         (assignee SET_NULL), AssetOwnerMap/DeptLeaderMap cascade (IPs become
         ownerless), AuditLog survives (actor SET_NULL); cannot delete self
         (400), deleting an admin needs admin role (403); -> 200
         {deleted, username, unassigned_open_tickets}
  POST /api/ops/<id>/close {note?} -> 待复测→已闭合 (IsOperator, else 403)
  POST /api/ops/<id>/reject {note?} -> 待复测→待修复打回 (IsOperator)
  POST /api/ops/<id>/ignore {reason, expires_at?} -> *→已忽略 (IsOperator;
       missing reason 422)

Misc (JWT on all; auditor read-only, POST as auditor 403):
  POST /api/auth/change-password {old_password, new_password} -> {jwt, user}
       (self-service for temp-password accounts; returns a fresh JWT)
  GET  /api/ops/sla-policies -> {results: [{severity, days,
       warn_days_before, source(table|fallback)}]} (admin only)
  PUT  /api/ops/sla-policies/<severity> {days 1-365, warn_days_before? 0-60}
       -> upsert (admin only; takes effect on next compute_due/escalation)
  GET  /api/dashboard?dept=&dept_prefix= -> {total, by_state{6 states},
       by_severity{4}, sla{overdue, at_risk, ok, no_due}, by_dept{一级部门:
       {total, open, closed, overdue}}} (dept exact; dept_prefix startswith;
       overdue = open + sla_due_at past, at_risk = due within 3d)
   GET  /api/audit?ticket_id=&actor= -> paginated {id, action, actor,
        ticket_id, entity, entity_id, diff_json, created_at}, newest-first;
        admin/operator/auditor only (others 403)

 Integration settings (admin only; page-editable, no backend restart;
 DB row wins over env fallback; secrets masked, audit action
 "integration.update" on entity "integration_setting"):
   GET  /api/ops/integrations -> {groups: [{id, label, fields: [{key,
        label, secret, configured, value?, hint?}]}]}; secret fields carry
        no value, only {key, label, secret: true, configured}
   PUT  /api/ops/integrations {key, value} -> {key, configured};
        unknown key 400; port 1-65535 int; bools true/false/1/0/yes/no/
        on/off; url keys must start with http(s)://; secret "" keeps the
        old value, non-secret "" clears the DB row (falls back to env)
   POST /api/ops/integrations/test {key: smtp|wecom.bot|wecom.login|cmdb,
        to?} -> {ok, detail}; unknown target 400; never 500
   GET  /api/imports/field-map -> {version, mapping} RSAS field-map viewer
        (operator only)

 No drf-spectacular: not installed and zero-new-deps preferred; this
 docstring IS the schema for the frontend lane.
 """

from __future__ import annotations

from django.urls import path

from apps.tickets.views import (
    AuditListView,
    DashboardView,
    IpSummaryView,
    MyTicketExportView,
    MyTicketListView,
    OpsAssignView,
    OpsBatchAssignView,
    OpsBatchCloseView,
    OpsBatchIgnoreView,
    OpsCloseView,
    OpsDelayDecideView,
    OpsDelayRequestListView,
    OpsDepartmentsView,
    OpsIgnoreView,
    OpsPoolExportView,
    OpsPoolView,
    OpsRejectView,
    OpsRemindView,
    OpsTicketCreateView,
    OpsTicketDeleteView,
    OpsTicketEditView,
    OpsUsersView,
    SlaPolicyView,
    TicketAttachmentUploadView,
    TicketDelayRequestView,
    TicketDelayView,
    TicketDetailView,
    TicketResumeView,
    TicketSubmitView,
    UserAdminDetailView,
    UserAdminView,
)

urlpatterns: list[object] = [
    path("tickets/my", MyTicketListView.as_view()),
    path("tickets/my/export", MyTicketExportView.as_view()),
    path("tickets/ip-summary", IpSummaryView.as_view()),
    path("tickets/<int:pk>", TicketDetailView.as_view()),
    path("tickets/<int:pk>/submit", TicketSubmitView.as_view()),
    path("tickets/<int:pk>/delay", TicketDelayView.as_view()),
    path("tickets/<int:pk>/delay-request", TicketDelayRequestView.as_view()),
    path("tickets/<int:pk>/resume", TicketResumeView.as_view()),
    path("tickets/<int:pk>/attachments", TicketAttachmentUploadView.as_view()),
    path("ops/delay-requests", OpsDelayRequestListView.as_view()),
    path("ops/delay-requests/<int:pk>/<str:action>", OpsDelayDecideView.as_view()),
    path("ops/pool", OpsPoolView.as_view()),
    path("ops/pool/export", OpsPoolExportView.as_view()),
    path("ops/tickets", OpsTicketCreateView.as_view()),
    path("ops/batch-assign", OpsBatchAssignView.as_view()),
    path("ops/batch-close", OpsBatchCloseView.as_view()),
    path("ops/batch-ignore", OpsBatchIgnoreView.as_view()),
    path("ops/remind", OpsRemindView.as_view()),
    path("ops/users", OpsUsersView.as_view()),
    path("ops/departments", OpsDepartmentsView.as_view()),
    path("ops/sla-policies", SlaPolicyView.as_view()),
    path("ops/sla-policies/<str:severity>", SlaPolicyView.as_view()),
    path("ops/<int:pk>/assign", OpsAssignView.as_view()),
    path("ops/<int:pk>/edit", OpsTicketEditView.as_view()),
    path("ops/<int:pk>", OpsTicketDeleteView.as_view()),
    path("ops/admin/users", UserAdminView.as_view()),
    path("ops/admin/users/<str:username>", UserAdminDetailView.as_view()),
    path("ops/<int:pk>/close", OpsCloseView.as_view()),
    path("ops/<int:pk>/reject", OpsRejectView.as_view()),
    path("ops/<int:pk>/ignore", OpsIgnoreView.as_view()),
    path("dashboard", DashboardView.as_view()),
    path("audit", AuditListView.as_view()),
]
