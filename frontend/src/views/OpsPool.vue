<template>
  <el-container>
    <el-header class="bar">
      <span>工单池（运营）</span>
      <span class="user">{{ auth.user?.username }} ({{ auth.user?.role }})</span>
      <el-button link @click="$router.push('/my')">我的工单</el-button>
      <el-button v-if="showAssets" link @click="$router.push('/ops/assets')">资产映射</el-button>
      <el-button v-if="showOps" link @click="$router.push('/ops/imports')">导入管理</el-button>
      <el-button link @click="$router.push('/ops/users')">用户管理</el-button>
      <el-button v-if="showAdmin" link @click="$router.push('/ops/config')">系统配置</el-button>
      <el-button v-if="showAudit" link @click="$router.push('/ops/audit')">审计日志</el-button>
    </el-header>
    <el-main>
      <el-tabs v-model="tab" @tab-change="onTabChange">
        <el-tab-pane label="全部" name="all" />
        <el-tab-pane label="无主" name="orphan" />
        <el-tab-pane label="未分配" name="unassigned" />
        <el-tab-pane label="逾期" name="overdue" />
        <el-tab-pane label="延期审批" name="delays" />
      </el-tabs>
      <el-card v-if="tab === 'delays'">
        <el-form inline>
          <el-form-item label="状态">
            <el-select v-model="delayStatus" placeholder="待审批" clearable style="width: 140px" @change="loadDelays">
              <el-option label="待审批" value="待审批" />
              <el-option label="已批准" value="已批准" />
              <el-option label="已驳回" value="已驳回" />
            </el-select>
          </el-form-item>
        </el-form>
        <el-table :data="delayRows" v-loading="loading" style="width: 100%">
          <el-table-column prop="ticket_ip" label="IP" width="150" />
          <el-table-column prop="ticket_title" label="标题" min-width="200" />
          <el-table-column prop="requested_by" label="申请人" width="120" />
          <el-table-column label="申请" width="170">
            <template #default="{ row }">{{ delayText(row) }}</template>
          </el-table-column>
          <el-table-column prop="reason" label="原因" min-width="180" />
          <el-table-column prop="status" label="状态" width="100" />
          <el-table-column label="操作" width="170" fixed="right">
            <template #default="{ row }">
              <template v-if="row.status === '待审批' && showOps">
                <el-button size="small" type="success" @click="onDecide(row, 'approve')">批准</el-button>
                <el-button size="small" type="warning" @click="onDecide(row, 'reject')">驳回</el-button>
              </template>
            </template>
          </el-table-column>
        </el-table>
      </el-card>
      <el-card v-else>
        <el-form inline :model="filters">
          <el-form-item label="状态">
            <el-select v-model="filters.state" placeholder="全部" clearable style="width: 140px">
              <el-option v-for="s in states" :key="s" :label="s" :value="s" />
            </el-select>
          </el-form-item>
          <el-form-item label="严重性">
            <el-select
              v-model="filters.severity"
              placeholder="全部"
              clearable
              multiple
              collapse-tags
              collapse-tags-tooltip
              style="width: 170px"
              @change="load(1)"
            >
              <el-option v-for="s in severities" :key="s" :label="s" :value="s" />
            </el-select>
          </el-form-item>
          <el-form-item label="搜索">
            <el-input v-model="filters.q" placeholder="IP/标题/CVE" clearable style="width: 220px" @keyup.enter="load(1)" />
          </el-form-item>
          <el-form-item label="一级部门">
            <el-select
              v-model="deptFirst"
              placeholder="全部"
              clearable
              style="width: 150px"
              @change="onDeptFirstChange"
            >
              <el-option v-for="d in deptTree.first" :key="d" :label="d" :value="d" />
            </el-select>
          </el-form-item>
          <el-form-item label="二级部门">
            <el-select
              v-model="deptSecond"
              placeholder="全部"
              clearable
              :disabled="!deptFirst"
              style="width: 150px"
              @change="load(1)"
            >
              <el-option v-for="d in secondOptions" :key="d" :label="secondLabel(d)" :value="d" />
            </el-select>
          </el-form-item>
          <el-form-item>
            <el-button type="primary" @click="load(1)">查询</el-button>
            <el-button v-if="showOps" @click="onExport">导出CSV</el-button>
            <el-button v-if="showOps" type="primary" plain @click="openCreate">新建工单</el-button>
            <el-button v-if="showOps" type="primary" plain :disabled="!selectedIds.length" @click="openBatchAssign">
              批量派单{{ selectedIds.length ? `（${selectedIds.length}）` : '' }}
            </el-button>
            <el-button v-if="showOps" type="warning" plain :disabled="!selectedIds.length" :loading="remindLoading" @click="onRemind">
              提醒负责人{{ selectedIds.length ? `（${selectedIds.length}）` : '' }}
            </el-button>
          </el-form-item>
        </el-form>

        <el-table
          :data="displayRows"
          v-loading="loading"
          style="width: 100%"
          :row-class-name="rowClass"
          @selection-change="onSelectionChange"
        >
          <el-table-column v-if="showOps" type="selection" width="42" />
          <el-table-column prop="severity" label="严重性" width="100">
            <template #default="{ row }"><SeverityTag :severity="String(row.severity ?? '')" /></template>
          </el-table-column>
          <el-table-column prop="state" label="状态" width="110">
            <template #default="{ row }"><StateTag :state="String(row.state ?? '')" /></template>
          </el-table-column>
          <el-table-column label="SLA" width="110">
            <template #default="{ row }"><SlaTag :sla-due-at="row.sla_due_at ?? null" /></template>
          </el-table-column>
          <el-table-column prop="ip" label="IP" width="140" />
          <el-table-column prop="port" label="端口" width="90" />
          <el-table-column prop="title" label="标题" min-width="200">
            <template #default="{ row }">
              <router-link :to="`/my/${row.id}`">{{ String(row.title ?? row.id) }}</router-link>
            </template>
          </el-table-column>
          <el-table-column prop="assignee" label="负责人" width="120">
            <template #default="{ row }">{{ row.assignee ?? '— 无主' }}</template>
          </el-table-column>
          <el-table-column label="发现日期" width="120">
            <template #default="{ row }">{{ String(row.first_seen_at ?? '').slice(0, 10) || '—' }}</template>
          </el-table-column>
          <el-table-column label="来源" width="140">
            <template #default="{ row }"
              ><span class="cell-ellipsis" :title="String(row.source ?? '—')">{{
                String(row.source ?? '—')
              }}</span></template
            >
          </el-table-column>
          <el-table-column label="操作" width="160" fixed="right">
            <template #default="{ row }">
              <el-button v-if="showOps" size="small" type="primary" @click="openAssign(row)">派单</el-button>
              <el-dropdown v-if="showOps" trigger="click" @command="(cmd: 'edit' | 'close' | 'reject' | 'ignore') => onMore(cmd, row)">
                <el-button size="small" text type="info">更多 ▾</el-button>
                <template #dropdown>
                  <el-dropdown-menu>
                    <el-dropdown-item command="edit">编辑</el-dropdown-item>
                    <el-dropdown-item command="close">关闭</el-dropdown-item>
                    <el-dropdown-item command="reject">驳回</el-dropdown-item>
                    <el-dropdown-item command="ignore">忽略</el-dropdown-item>
                  </el-dropdown-menu>
                </template>
              </el-dropdown>
            </template>
          </el-table-column>
        </el-table>

        <el-pagination
          layout="total, prev, pager, next"
          :total="total"
          :page-size="pageSize"
          :current-page="page"
          @current-change="load"
          style="margin-top: 12px"
        />
      </el-card>

      <el-dialog v-model="dlg.open" :title="dlgTitle">
        <el-form :model="dlg" label-width="80px">
          <el-form-item v-if="dlg.kind === 'ignore'" label="原因（必填）">
            <el-input v-model="dlg.text" type="textarea" :rows="3" placeholder="必填：忽略原因" />
          </el-form-item>
          <el-form-item v-else label="备注">
            <el-input v-model="dlg.text" type="textarea" :rows="3" placeholder="选填：备注" />
          </el-form-item>
        </el-form>
        <template #footer>
          <el-button @click="dlg.open = false">取消</el-button>
          <el-button type="primary" :loading="acting" @click="onAct">确认</el-button>
        </template>
      </el-dialog>

      <el-dialog v-model="assignDlg.open" title="手工派单">
        <el-form label-width="80px">
          <el-form-item label="工单">
            <span>#{{ assignDlg.id }}（当前：{{ assignDlg.current ?? '无主' }}）</span>
          </el-form-item>
          <el-form-item label="负责人">
            <el-select v-model="assignDlg.username" filterable placeholder="选择处理人" style="width: 100%">
              <el-option
                v-for="u in assignableUsers"
                :key="u.username"
                :label="`${u.username}${u.dept ? `（${u.dept}）` : ''}`"
                :value="u.username"
              />
            </el-select>
          </el-form-item>
        </el-form>
        <template #footer>
          <el-button @click="assignDlg.open = false">取消</el-button>
          <el-button type="primary" :loading="acting" @click="onAssign">确认派单</el-button>
        </template>
      </el-dialog>

      <el-dialog v-model="batchDlg.open" title="批量操作" width="460px">
        <p>已选 <b>{{ selectedIds.length }}</b> 张工单（不可流转的自动跳过并报告）。</p>
        <el-form label-width="80px">
          <el-form-item label="负责人">
            <el-select v-model="batchDlg.username" filterable placeholder="批量派单时选择处理人" style="width: 100%">
              <el-option
                v-for="u in assignableUsers"
                :key="u.username"
                :label="`${u.username}${u.dept ? `（${u.dept}）` : ''}`"
                :value="u.username"
              />
            </el-select>
          </el-form-item>
          <el-form-item label="原因/备注">
            <el-input v-model="batchDlg.note" placeholder="批量忽略必填；批量关闭选填" clearable />
          </el-form-item>
        </el-form>
        <template #footer>
          <el-button @click="batchDlg.open = false">取消</el-button>
          <el-button type="primary" :loading="acting" @click="onBatchAssign">批量派单</el-button>
          <el-button type="success" :loading="acting" @click="onBatchClose">批量关闭</el-button>
          <el-button type="info" :loading="acting" @click="onBatchIgnore">批量忽略</el-button>
        </template>
      </el-dialog>

      <el-dialog v-model="createDlg.open" title="新建工单（第三方漏洞手工录入）" width="560px">
        <el-form :model="createDlg" label-width="90px">
          <el-form-item label="IP" required>
            <el-input v-model="createDlg.ip" placeholder="如 10.9.0.12" clearable style="width: 240px" />
          </el-form-item>
          <el-form-item label="端口">
            <el-input-number v-model="createDlg.port" :min="1" :max="65535" />
          </el-form-item>
          <el-form-item label="严重性" required>
            <el-select v-model="createDlg.severity" placeholder="请选择" style="width: 240px">
              <el-option v-for="s in createSeverities" :key="s" :label="s" :value="s" />
            </el-select>
          </el-form-item>
          <el-form-item label="漏洞标题" required>
            <el-input v-model="createDlg.title" placeholder="如 渗透测试发现后台弱口令" clearable />
          </el-form-item>
          <el-form-item label="CVE">
            <el-input v-model="createDlg.cve" placeholder="选填，如 CVE-2026-0001" clearable style="width: 240px" />
          </el-form-item>
          <el-form-item label="来源">
            <el-input
              v-model="createDlg.source"
              placeholder="选填，如 安恒渗透测试，不填为手工录入"
              clearable
              maxlength="64"
              show-word-limit
            />
          </el-form-item>
          <el-form-item label="处理人">
            <el-select v-model="createDlg.assignee" filterable clearable placeholder="不选则按IP自动派单" style="width: 100%">
              <el-option
                v-for="u in assignableUsers"
                :key="u.username"
                :label="`${u.username}${u.dept ? `（${u.dept}）` : ''}`"
                :value="u.username"
              />
            </el-select>
          </el-form-item>
          <el-form-item label="描述">
            <el-input v-model="createDlg.description" type="textarea" :rows="3" placeholder="选填：第三方报告原文/影响范围" />
          </el-form-item>
        </el-form>
        <template #footer>
          <el-button @click="createDlg.open = false">取消</el-button>
          <el-button type="primary" :loading="acting" @click="onCreate">确认新建</el-button>
        </template>
      </el-dialog>

      <el-dialog v-model="editDlg.open" title="编辑工单（IP/端口不可改）" width="560px">
        <el-form :model="editDlg" label-width="90px">
          <el-form-item label="漏洞标题" required>
            <el-input v-model="editDlg.title" clearable />
          </el-form-item>
          <el-form-item label="严重性" required>
            <el-select v-model="editDlg.severity" placeholder="请选择" style="width: 240px">
              <el-option v-for="s in createSeverities" :key="s" :label="s" :value="s" />
            </el-select>
          </el-form-item>
          <el-form-item label="CVE">
            <el-input v-model="editDlg.cve" placeholder="留空=不改" clearable style="width: 240px" />
          </el-form-item>
          <el-form-item label="来源">
            <el-input
              v-model="editDlg.source"
              placeholder="留空=不改，填新文本则换批次"
              clearable
              maxlength="64"
              show-word-limit
            />
          </el-form-item>
          <el-form-item label="描述">
            <el-input v-model="editDlg.description" type="textarea" :rows="3" placeholder="留空=不改" />
          </el-form-item>
          <el-form-item label="解决方案">
            <el-input v-model="editDlg.solution" type="textarea" :rows="3" placeholder="留空=不改" />
          </el-form-item>
        </el-form>
        <p class="muted">改严重性会按发现日期重算 SLA；所有修改记审计时间线。</p>
        <template #footer>
          <el-button @click="editDlg.open = false">取消</el-button>
          <el-button v-if="showOps" type="danger" plain :loading="acting" @click="onDeleteFromEditDlg">删除工单</el-button>
          <el-button type="primary" :loading="acting" @click="onEditSave">保存修改</el-button>
        </template>
      </el-dialog>
    </el-main>
  </el-container>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { fetchOpsPool, fetchAssignableUsers, fetchDelayRequests, fetchDepartments, decideDelayRequest, opsAssign, opsBatchAssign, opsBatchClose, opsBatchIgnore, opsClose, opsCreateTicket, opsEditTicket, opsDeleteTicket, opsIgnore, opsReject, exportPoolCsv, remindTickets } from '../api/ops'
import type { AssignableUser, DelayRequest, DeptTree } from '../api/ops'
import type { TicketItem } from '../api/tickets'
import { buildPoolQuery, type PoolTab } from '../utils/ops'
import { canShowAuditButton, canShowOpsButton, slaCountdown } from '../utils/tickets'
import { useAuthStore } from '../stores/auth'
import SlaTag from '../components/SlaTag.vue'
import StateTag from '../components/StateTag.vue'
import SeverityTag from '../components/SeverityTag.vue'

const auth = useAuthStore()
auth.hydrate()

const states = ['待分配', '待修复', '待复测', '已闭合', '已延期', '已忽略']
const severities = ['严重', '高', '中', '低']
const tab = ref<PoolTab>('all')
const filters = reactive<{ state: string; severity: string[]; q: string }>({ state: '', severity: [], q: '' })

const deptTree = ref<DeptTree>({ first: [], tree: {}, count: 0 })
const deptFirst = ref('')
const deptSecond = ref('')
const secondOptions = computed(() => (deptFirst.value ? (deptTree.value.tree[deptFirst.value] ?? []) : []))

function secondLabel(full: string): string {
  return deptFirst.value && full.startsWith(deptFirst.value) ? full.slice(deptFirst.value.length + 1) : full
}

function deptParams(): { dept?: string; dept_prefix?: string } {
  if (!deptFirst.value) return {}
  if (deptSecond.value) return { dept: deptSecond.value, dept_prefix: deptFirst.value }
  return { dept_prefix: deptFirst.value }
}

function onDeptFirstChange() {
  deptSecond.value = ''
  void load(1)
}

async function loadDepartments() {
  try {
    deptTree.value = await fetchDepartments()
  } catch {
    deptTree.value = { first: [], tree: {}, count: 0 }
  }
}
const rows = ref<TicketItem[]>([])
const total = ref(0)
const page = ref(1)
const pageSize = ref(20)
const loading = ref(false)
const acting = ref(false)

const showOps = computed(() => canShowOpsButton(auth.role))
const showAudit = computed(() => canShowAuditButton(auth.role))
const showAssets = computed(() => ['admin', 'operator', 'leader'].includes(auth.role))
const showAdmin = computed(() => auth.role === 'admin')

const displayRows = computed(() => {
  if (tab.value !== 'overdue') return rows.value
  return rows.value.filter((r) => slaCountdown(r.sla_due_at as string | null | undefined).overdue)
})

function rowClass({ row }: { row: TicketItem }): string {
  return row.assignee == null ? 'orphan-row' : ''
}

const dlg = reactive<{ open: boolean; kind: 'close' | 'reject' | 'ignore'; id: string | number | null; text: string }>({
  open: false,
  kind: 'close',
  id: null,
  text: '',
})
const dlgTitle = computed(() => ({ close: '关闭工单', reject: '驳回工单', ignore: '忽略工单' })[dlg.kind])

function openDlg(kind: 'close' | 'reject' | 'ignore', row: TicketItem) {
  dlg.kind = kind
  dlg.id = row.id
  dlg.text = ''
  dlg.open = true
}

function onMore(cmd: 'edit' | 'close' | 'reject' | 'ignore', row: TicketItem) {
  if (cmd === 'edit') openEdit(row)
  else openDlg(cmd, row)
}

const editDlg = reactive({
  open: false,
  id: null as string | number | null,
  title: '',
  severity: '',
  cve: '',
  source: '',
  description: '',
  solution: '',
})

function openEdit(row: TicketItem) {
  editDlg.id = row.id
  editDlg.title = String(row.title ?? '')
  editDlg.severity = String(row.severity ?? '')
  editDlg.cve = ''
  editDlg.source = ''
  editDlg.description = ''
  editDlg.solution = ''
  editDlg.open = true
}

async function onEditSave() {
  if (editDlg.id == null) return
  if (!editDlg.title.trim() || !editDlg.severity) {
    ElMessage.warning('请填写标题和严重性')
    return
  }
  acting.value = true
  try {
    await opsEditTicket(editDlg.id, {
      title: editDlg.title.trim(),
      severity: editDlg.severity,
      ...(editDlg.cve.trim() ? { cve: editDlg.cve.trim() } : {}),
      ...(editDlg.source.trim() ? { source: editDlg.source.trim() } : {}),
      ...(editDlg.description.trim() ? { description: editDlg.description.trim() } : {}),
      ...(editDlg.solution.trim() ? { solution: editDlg.solution.trim() } : {}),
    })
    ElMessage.success(`已保存 #${editDlg.id} 的修改（审计已记录）`)
    editDlg.open = false
    await load(page.value)
  } catch (e: unknown) {
    const err = e as { response?: { data?: { friendly?: string; detail?: string } } }
    ElMessage.error(err.response?.data?.friendly ?? err.response?.data?.detail ?? '保存失败')
  } finally {
    acting.value = false
  }
}

async function onDeleteFromEditDlg() {
  if (editDlg.id == null) return
  try {
    await ElMessageBox.confirm(
      `确定永久删除工单 #${editDlg.id}？证据与时间线一并删除（审计留痕），不可恢复。`,
      '删除工单',
      { type: 'warning', confirmButtonText: '删除', cancelButtonText: '取消' },
    )
  } catch {
    return
  }
  acting.value = true
  try {
    await opsDeleteTicket(editDlg.id)
    ElMessage.success(`工单 #${editDlg.id} 已删除`)
    editDlg.open = false
    await load(page.value)
  } catch (e: unknown) {
    const err = e as { response?: { data?: { friendly?: string; detail?: string } } }
    ElMessage.error(err.response?.data?.friendly ?? err.response?.data?.detail ?? '删除失败')
  } finally {
    acting.value = false
  }
}

const assignableUsers = ref<AssignableUser[]>([])
const assignDlg = reactive<{ open: boolean; id: string | number | null; current: string | null; username: string }>({
  open: false,
  id: null,
  current: null,
  username: '',
})

async function openAssign(row: TicketItem) {
  assignDlg.id = row.id
  assignDlg.current = (row.assignee as string | null) ?? null
  assignDlg.username = ''
  assignDlg.open = true
  if (!assignableUsers.value.length) {
    try {
      assignableUsers.value = await fetchAssignableUsers()
    } catch (e: unknown) {
      const err = e as { response?: { data?: { friendly?: string; detail?: string } } }
      ElMessage.error(err.response?.data?.friendly ?? err.response?.data?.detail ?? '加载用户列表失败')
    }
  }
}

async function onAssign() {
  if (assignDlg.id == null || !assignDlg.username) {
    ElMessage.warning('请选择负责人')
    return
  }
  acting.value = true
  try {
    await opsAssign(assignDlg.id, assignDlg.username)
    ElMessage.success(`已派单给 ${assignDlg.username}`)
    assignDlg.open = false
    await load(page.value)
  } catch (e: unknown) {
    const err = e as { response?: { data?: { friendly?: string; detail?: string } } }
    ElMessage.error(err.response?.data?.friendly ?? err.response?.data?.detail ?? '派单失败')
  } finally {
    acting.value = false
  }
}

const selectedIds = ref<Array<string | number>>([])
const batchDlg = reactive<{ open: boolean; username: string; note: string }>({ open: false, username: '', note: '' })
const remindLoading = ref(false)

function onSelectionChange(rows: TicketItem[]) {
  selectedIds.value = rows.map((r) => r.id)
}

async function onRemind() {
  if (!selectedIds.value.length) return
  try {
    await ElMessageBox.confirm(
      `将为所选 ${selectedIds.value.length} 张工单发送提醒邮件。同一负责人合并成一封；同一工单 24 小时内只提醒一次（重复选择会自动跳过）；无负责人的工单会被跳过。继续？`,
      '发送处理提醒',
      { type: 'warning', confirmButtonText: '发送', cancelButtonText: '取消' },
    )
  } catch {
    return
  }
  remindLoading.value = true
  try {
    const res = await remindTickets(selectedIds.value)
    ElMessage.success(
      `已发送 ${res.sent_emails} 封（${res.reminded_tickets} 张工单）${res.skipped_cooldown ? `，${res.skipped_cooldown} 张在冷却期内跳过` : ''}${res.skipped_unassigned ? `，${res.skipped_unassigned} 张无负责人跳过` : ''}`,
    )
    await load(page.value)
  } catch (e: unknown) {
    const err = e as { response?: { data?: { friendly?: string; detail?: string } } }
    ElMessage.error(err.response?.data?.friendly ?? err.response?.data?.detail ?? '发送提醒失败')
  } finally {
    remindLoading.value = false
  }
}

async function openBatchAssign() {
  if (!selectedIds.value.length) return
  batchDlg.username = ''
  batchDlg.note = ''
  batchDlg.open = true
  if (!assignableUsers.value.length) {
    try {
      assignableUsers.value = await fetchAssignableUsers()
    } catch (e: unknown) {
      const err = e as { response?: { data?: { friendly?: string; detail?: string } } }
      ElMessage.error(err.response?.data?.friendly ?? err.response?.data?.detail ?? '加载用户列表失败')
    }
  }
}

async function onBatchAssign() {
  if (!batchDlg.username) {
    ElMessage.warning('请选择负责人')
    return
  }
  acting.value = true
  try {
    const res = await opsBatchAssign(selectedIds.value, batchDlg.username)
    const skipped = res.skipped?.length ? `，跳过 ${res.skipped.length}（${res.skipped.map((s) => `#${s.id} ${s.reason}`).join('；')}）` : ''
    ElMessage.success(`已批量派单 ${res.assigned} 张给 ${batchDlg.username}${skipped}`)
    batchDlg.open = false
    await load(page.value)
  } catch (e: unknown) {
    const err = e as { response?: { data?: { friendly?: string; detail?: string } } }
    ElMessage.error(err.response?.data?.friendly ?? err.response?.data?.detail ?? '批量派单失败')
  } finally {
    acting.value = false
  }
}

function skippedText(skipped: Array<{ id: number; reason: string }>): string {
  return skipped?.length ? `，跳过 ${skipped.length}（${skipped.map((s) => `#${s.id} ${s.reason}`).join('；')}）` : ''
}

async function onBatchClose() {
  acting.value = true
  try {
    const res = await opsBatchClose(selectedIds.value, batchDlg.note.trim() || undefined)
    ElMessage.success(`已批量关闭 ${res.closed} 张${skippedText(res.skipped)}`)
    batchDlg.open = false
    await load(page.value)
  } catch (e: unknown) {
    const err = e as { response?: { data?: { friendly?: string; detail?: string } } }
    ElMessage.error(err.response?.data?.friendly ?? err.response?.data?.detail ?? '批量关闭失败')
  } finally {
    acting.value = false
  }
}

async function onBatchIgnore() {
  if (!batchDlg.note.trim()) {
    ElMessage.warning('批量忽略必须填写原因')
    return
  }
  acting.value = true
  try {
    const res = await opsBatchIgnore(selectedIds.value, batchDlg.note.trim())
    ElMessage.success(`已批量忽略 ${res.ignored} 张${skippedText(res.skipped)}`)
    batchDlg.open = false
    await load(page.value)
  } catch (e: unknown) {
    const err = e as { response?: { data?: { friendly?: string; detail?: string } } }
    ElMessage.error(err.response?.data?.friendly ?? err.response?.data?.detail ?? '批量忽略失败')
  } finally {
    acting.value = false
  }
}

const createSeverities = ['严重', '高', '中', '低']
const createDlg = reactive({
  open: false,
  ip: '',
  port: 443,
  severity: '',
  title: '',
  cve: '',
  assignee: '',
  source: '',
  description: '',
})

async function ensureAssignableUsers() {
  if (!assignableUsers.value.length) {
    try {
      assignableUsers.value = await fetchAssignableUsers()
    } catch (e: unknown) {
      const err = e as { response?: { data?: { friendly?: string; detail?: string } } }
      ElMessage.error(err.response?.data?.friendly ?? err.response?.data?.detail ?? '加载用户列表失败')
    }
  }
}

async function openCreate() {
  createDlg.ip = ''
  createDlg.port = 443
  createDlg.severity = ''
  createDlg.title = ''
  createDlg.cve = ''
  createDlg.assignee = ''
  createDlg.source = ''
  createDlg.description = ''
  createDlg.open = true
  await ensureAssignableUsers()
}

async function onCreate() {
  if (!createDlg.ip.trim() || !createDlg.severity || !createDlg.title.trim()) {
    ElMessage.warning('请填写 IP、严重性和漏洞标题')
    return
  }
  acting.value = true
  try {
    const created = await opsCreateTicket({
      ip: createDlg.ip.trim(),
      port: createDlg.port,
      severity: createDlg.severity,
      title: createDlg.title.trim(),
      ...(createDlg.cve.trim() ? { cve: createDlg.cve.trim() } : {}),
      ...(createDlg.assignee ? { assignee: createDlg.assignee } : {}),
      ...(createDlg.source.trim() ? { source: createDlg.source.trim() } : {}),
      ...(createDlg.description.trim() ? { description: createDlg.description.trim() } : {}),
    })
    ElMessage.success(`已新建工单 #${created.id}${created.assignee ? `，已派给 ${created.assignee}` : '，进入无主池'}`)
    createDlg.open = false
    await load(1)
  } catch (e: unknown) {
    const err = e as { response?: { data?: { friendly?: string; detail?: string } } }
    ElMessage.error(err.response?.data?.friendly ?? err.response?.data?.detail ?? '新建失败')
  } finally {
    acting.value = false
  }
}

async function onExport() {
  try {
    await exportPoolCsv(
      buildPoolQuery({
        tab: tab.value,
        state: filters.state || undefined,
        severity: filters.severity || undefined,
        q: filters.q || undefined,
        ...deptParams(),
      }),
    )
    ElMessage.success('CSV 已导出')
  } catch (e: unknown) {
    const err = e as { response?: { status?: number } }
    ElMessage.error(err.response?.status === 403 ? '无权限（运营/负责人可导出）' : '导出失败')
  }
}

async function load(p = 1) {
  loading.value = true
  page.value = p
  try {
    const query = buildPoolQuery({
      tab: tab.value,
      state: filters.state || undefined,
      severity: filters.severity || undefined,
      q: filters.q || undefined,
      ...deptParams(),
      page: p,
      page_size: pageSize.value,
    })
    const res = await fetchOpsPool(query)
    rows.value = res.results
    total.value = res.count
  } catch (e: unknown) {
    const err = e as { response?: { status?: number; data?: { friendly?: string; detail?: string } } }
    if (err.response?.status === 403) {
      ElMessage.error(err.response?.data?.friendly ?? '无权限：工单池仅运营/负责人可见（owner 访问 403）。')
    } else {
      ElMessage.error(err.response?.data?.friendly ?? err.response?.data?.detail ?? '加载工单池失败')
    }
  } finally {
    loading.value = false
  }
}

const delayRows = ref<DelayRequest[]>([])
const delayStatus = ref('待审批')

function onTabChange() {
  if (tab.value === 'delays') void loadDelays()
  else void load(1)
}

function delayText(row: DelayRequest): string {
  if (row.delay_days != null) return `${row.delay_days} 天`
  return String(row.delay_until ?? '-')
}

async function loadDelays() {
  loading.value = true
  try {
    delayRows.value = await fetchDelayRequests(delayStatus.value || undefined)
  } catch (e: unknown) {
    const err = e as { response?: { data?: { friendly?: string; detail?: string } } }
    ElMessage.error(err.response?.data?.friendly ?? err.response?.data?.detail ?? '加载延期申请失败')
  } finally {
    loading.value = false
  }
}

async function onDecide(row: DelayRequest, action: 'approve' | 'reject') {
  let note = ''
  if (action === 'reject') {
    const input = window.prompt('驳回备注（选填）')
    if (input == null) return
    note = input
  }
  try {
    await decideDelayRequest(row.id, action, note || undefined)
    ElMessage.success(action === 'approve' ? '已批准延期' : '已驳回')
    await loadDelays()
    await load(page.value)
  } catch (e: unknown) {
    const err = e as { response?: { data?: { friendly?: string; detail?: string } } }
    ElMessage.error(err.response?.data?.friendly ?? err.response?.data?.detail ?? '审批失败')
  }
}

async function onAct() {
  if (dlg.id == null) return
  if (dlg.kind === 'ignore' && !dlg.text.trim()) {
    ElMessage.warning('请填写忽略原因')
    return
  }
  acting.value = true
  try {
    if (dlg.kind === 'close') await opsClose(dlg.id, dlg.text.trim() || undefined)
    else if (dlg.kind === 'reject') await opsReject(dlg.id, dlg.text.trim() || undefined)
    else await opsIgnore(dlg.id, dlg.text.trim())
    ElMessage.success('操作成功')
    dlg.open = false
    await load(page.value)
  } catch (e: unknown) {
    const err = e as { response?: { status?: number; data?: { friendly?: string; detail?: string } } }
    ElMessage.error(err.response?.data?.friendly ?? err.response?.data?.detail ?? '操作失败')
  } finally {
    acting.value = false
  }
}

onMounted(() => {
  void loadDepartments()
  void load(1)
})
</script>

<style scoped>
.bar {
  display: flex;
  align-items: center;
  gap: 12px;
}
.user {
  margin-left: auto;
  color: #666;
  font-size: 13px;
}
:deep(.orphan-row) {
  background-color: #fff7e6;
}
.cell-ellipsis {
  display: inline-block;
  max-width: 100%;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  vertical-align: bottom;
}
.muted {
  color: #8a94a6;
  font-size: 12px;
}
</style>
