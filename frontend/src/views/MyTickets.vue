<template>
  <el-container>
    <el-header class="bar">
      <span>{{ auth.role === 'auditor' ? '全部工单（审计只读）' : '我的工单' }}</span>
      <span class="user">{{ auth.user?.username }} ({{ auth.user?.role }})</span>
      <el-button link @click="pwdOpen = true">修改密码</el-button>
      <el-button link @click="$router.push('/mfa')">二次验证</el-button>
      <el-button link @click="onLogout">退出</el-button>
      <el-button v-if="showOps" @click="$router.push('/ops')">运营后台</el-button>
      <el-button v-if="showAudit" @click="$router.push('/ops/audit')">审计日志</el-button>
    </el-header>
    <el-main>
      <el-card>
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
              style="width: 200px"
              @change="load(1)"
            >
              <el-option v-for="s in severities" :key="s" :label="s" :value="s" />
            </el-select>
          </el-form-item>
          <el-form-item label="搜索">
            <el-input v-model="filters.q" placeholder="IP/标题/端口" clearable style="width: 220px" @keyup.enter="load(1)" />
          </el-form-item>
          <el-form-item>
            <el-button type="primary" @click="load(1)">查询</el-button>
            <el-button @click="onExport">导出CSV</el-button>
            <el-switch v-model="ipSummaryMode" active-text="按IP汇总" style="margin-left: 12px" />
          </el-form-item>
        </el-form>

        <el-table v-if="!ipSummaryMode" :data="rows" v-loading="loading" style="width: 100%">
          <el-table-column prop="severity" label="严重性" width="100">
            <template #default="{ row }"><SeverityTag :severity="String(row.severity ?? '')" /></template>
          </el-table-column>
          <el-table-column prop="state" label="状态" width="110">
            <template #default="{ row }"><StateTag :state="String(row.state ?? '')" /></template>
          </el-table-column>
          <el-table-column label="SLA" width="130">
            <template #default="{ row }"><SlaTag :sla-due-at="row.sla_due_at ?? null" /></template>
          </el-table-column>
          <el-table-column prop="ip" label="IP" width="150" />
          <el-table-column prop="port" label="端口" width="90" />
          <el-table-column prop="title" label="标题" min-width="220">
            <template #default="{ row }">
              <router-link :to="`/my/${row.id}`">{{ String(row.title ?? row.id) }}</router-link>
            </template>
          </el-table-column>
          <el-table-column label="发现日期" width="120">
            <template #default="{ row }">{{ String(row.first_seen_at ?? '').slice(0, 10) || '—' }}</template>
          </el-table-column>
          <el-table-column label="来源" width="120">
            <template #default="{ row }"
              ><span class="cell-ellipsis" :title="String(row.source ?? '—')">{{
                String(row.source ?? '—')
              }}</span></template
            >
          </el-table-column>
          <el-table-column prop="assignee" label="负责人" width="120" />
        </el-table>

        <el-table
          v-else
          :data="ipSummary"
          v-loading="loading"
          style="width: 100%"
          row-key="ip"
          @expand-change="onExpandIp"
        >
          <el-table-column type="expand">
            <template #default="{ row }">
              <div v-if="ipTicketsLoading[row.ip]" class="muted" style="padding: 8px 24px">加载中…</div>
              <el-table
                v-else
                :data="ipTickets[row.ip] ?? []"
                size="small"
                :show-header="false"
                style="width: 100%"
              >
                <el-table-column label="标题" min-width="240">
                  <template #default="{ row: t }">
                    <router-link :to="`/my/${t.id}`">{{ String(t.title ?? t.id) }}</router-link>
                  </template>
                </el-table-column>
                <el-table-column label="严重性" width="90">
                  <template #default="{ row: t }"><SeverityTag :severity="String(t.severity ?? '')" /></template>
                </el-table-column>
                <el-table-column label="状态" width="110">
                  <template #default="{ row: t }"><StateTag :state="String(t.state ?? '')" /></template>
                </el-table-column>
                <el-table-column label="SLA" width="120">
                  <template #default="{ row: t }"><SlaTag :sla-due-at="t.sla_due_at ?? null" /></template>
                </el-table-column>
                <el-table-column label="发现日期" width="120">
                  <template #default="{ row: t }">{{
                    String(t.first_seen_at ?? '').slice(0, 10) || '—'
                  }}</template>
                </el-table-column>
              </el-table>
            </template>
          </el-table-column>
          <el-table-column prop="ip" label="IP" width="160" />
          <el-table-column prop="total" label="工单数" width="100" />
          <el-table-column prop="overdue" label="逾期数" width="100">
            <template #default="{ row }">
              <el-tag :type="row.overdue > 0 ? 'danger' : 'success'" size="small">{{ row.overdue }}</el-tag>
            </template>
          </el-table-column>
          <el-table-column label="严重性分布" min-width="200">
            <template #default="{ row }">{{ formatSev(row.severities) }}</template>
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
    </el-main>

    <el-dialog v-model="pwdOpen" title="修改密码" width="420px">
      <el-form label-width="90px">
        <el-form-item label="旧密码">
          <el-input v-model="pwdForm.old" type="password" show-password autocomplete="current-password" />
        </el-form-item>
        <el-form-item label="新密码">
          <el-input v-model="pwdForm.next" type="password" show-password placeholder="至少8位" autocomplete="new-password" />
        </el-form-item>
        <el-form-item label="确认新密码">
          <el-input v-model="pwdForm.confirm" type="password" show-password autocomplete="new-password" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="pwdOpen = false">取消</el-button>
        <el-button type="primary" :loading="pwdLoading" @click="onChangePassword">确认修改</el-button>
      </template>
    </el-dialog>
  </el-container>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { fetchMyTickets, fetchIpSummary, exportMyTicketsCsv, changePassword, type TicketItem, type IpSummaryRow } from '../api/tickets'
import { buildMyTicketsQuery, canShowAuditButton, canShowOpsButton, groupTicketsByIp } from '../utils/tickets'
import { useAuthStore } from '../stores/auth'
import SlaTag from '../components/SlaTag.vue'
import StateTag from '../components/StateTag.vue'
import SeverityTag from '../components/SeverityTag.vue'

const router = useRouter()
const auth = useAuthStore()
auth.hydrate()

const states = ['待分配', '待修复', '待复测', '已闭合', '已延期', '已忽略']
const severities = ['严重', '高', '中', '低']

const filters = reactive<{ state: string; severity: string[]; q: string }>({ state: '', severity: [], q: '' })
const rows = ref<TicketItem[]>([])
const total = ref(0)
const page = ref(1)
const pageSize = ref(20)
const loading = ref(false)
const ipSummaryMode = ref(false)

const showOps = computed(() => canShowOpsButton(auth.role))
const showAudit = computed(() => canShowAuditButton(auth.role))
const serverSummary = ref<IpSummaryRow[]>([])
const ipSummary = computed<IpSummaryRow[]>(() => serverSummary.value.length > 0 ? serverSummary.value : groupTicketsByIp(rows.value))

const ipTickets = ref<Record<string, TicketItem[]>>({})
const ipTicketsLoading = ref<Record<string, boolean>>({})

async function onExpandIp(row: IpSummaryRow, expanded: IpSummaryRow[]) {
  const ip = row.ip
  if (!expanded.some((r) => r.ip === ip)) return
  if (ipTickets.value[ip] || ipTicketsLoading.value[ip]) return
  ipTicketsLoading.value[ip] = true
  try {
    const res = await fetchMyTickets({ ...filters, q: ip, page: 1, page_size: 100 })
    ipTickets.value[ip] = res.results.filter((t) => String(t.ip) === ip)
  } catch {
    ipTickets.value[ip] = []
  } finally {
    ipTicketsLoading.value[ip] = false
  }
}

function formatSev(sev: Record<string, number>): string {
  return Object.entries(sev)
    .map(([k, v]) => `${k}×${v}`)
    .join(' ')
}

async function load(p = 1) {
  loading.value = true
  page.value = p
  ipTickets.value = {}
  ipTicketsLoading.value = {}
  try {
    const query = buildMyTicketsQuery({ ...filters, page: p, page_size: pageSize.value })
    const res = await fetchMyTickets(query)
    rows.value = res.results
    total.value = res.count
    if (ipSummaryMode.value) {
      try {
        serverSummary.value = await fetchIpSummary({ ...filters })
      } catch {
        serverSummary.value = []
      }
    } else {
      serverSummary.value = []
    }
  } catch (e: unknown) {
    const err = e as { response?: { data?: { friendly?: string; detail?: string } } }
    ElMessage.error(err.response?.data?.friendly ?? err.response?.data?.detail ?? '加载工单失败')
  } finally {
    loading.value = false
  }
}

function onLogout() {
  auth.logout()
  void router.push('/login')
}

async function onExport() {
  try {
    await exportMyTicketsCsv({ ...filters })
    ElMessage.success('已导出当前筛选的工单')
  } catch (e: unknown) {
    const err = e as { response?: { data?: { friendly?: string; detail?: string } } }
    ElMessage.error(err.response?.data?.friendly ?? err.response?.data?.detail ?? '导出失败')
  }
}

const pwdOpen = ref(false)
const pwdLoading = ref(false)
const pwdForm = reactive({ old: '', next: '', confirm: '' })

async function onChangePassword() {
  if (!pwdForm.old || !pwdForm.next) {
    ElMessage.warning('请填写旧密码和新密码')
    return
  }
  if (pwdForm.next.length < 8) {
    ElMessage.warning('新密码至少8位')
    return
  }
  if (pwdForm.next !== pwdForm.confirm) {
    ElMessage.warning('两次输入的新密码不一致')
    return
  }
  pwdLoading.value = true
  try {
    const res = await changePassword(pwdForm.old, pwdForm.next)
    localStorage.setItem('vuln_jwt', res.jwt)
    ElMessage.success('密码已修改')
    pwdOpen.value = false
    pwdForm.old = ''
    pwdForm.next = ''
    pwdForm.confirm = ''
  } catch (e: unknown) {
    const err = e as { response?: { data?: { friendly?: string; detail?: string } } }
    ElMessage.error(err.response?.data?.friendly ?? err.response?.data?.detail ?? '修改失败')
  } finally {
    pwdLoading.value = false
  }
}

onMounted(() => {
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
.cell-ellipsis {
  display: inline-block;
  max-width: 100%;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  vertical-align: bottom;
}
</style>
