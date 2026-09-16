<template>
  <el-container>
    <el-header class="bar">
      <span>系统配置（管理员）</span>
      <el-button link @click="$router.push('/ops')">返回工单池</el-button>
    </el-header>
    <el-main>
      <el-card header="SLA 策略（按严重性配置）">
        <p class="muted">修改即时生效：新工单与重开工单按新时长计算 SLA；已有工单的截止时间不变。</p>
        <el-table :data="slaRows" style="width: 100%" v-loading="slaLoading">
          <el-table-column prop="severity" label="严重性" width="120" />
          <el-table-column label="SLA（天）" width="160">
            <template #default="{ row }">
              <el-input-number v-model="row.days" :min="1" :max="365" size="small" />
            </template>
          </el-table-column>
          <el-table-column label="提前预警（天）" width="170">
            <template #default="{ row }">
              <el-input-number v-model="row.warn_days_before" :min="0" :max="60" size="small" />
            </template>
          </el-table-column>
          <el-table-column label="来源" width="110">
            <template #default="{ row }">
              <el-tag :type="row.source === 'table' ? 'success' : 'info'" size="small">
                {{ row.source === 'table' ? '已自定义' : '默认值' }}
              </el-tag>
            </template>
          </el-table-column>
          <el-table-column label="操作" width="120">
            <template #default="{ row }">
              <el-button size="small" type="primary" :loading="slaSaving === row.severity" @click="onSaveSla(row)">
                保存
              </el-button>
            </template>
          </el-table-column>
        </el-table>
      </el-card>

      <el-card header="看板概览（GET /api/dashboard）" style="margin-top: 12px">
        <el-form inline :model="dashForm" @submit.prevent>
          <el-form-item label="精确部门">
            <el-input v-model="dashForm.dept" placeholder="选填 ?dept=" clearable style="width: 180px" />
          </el-form-item>
          <el-form-item label="一级部门">
            <el-input v-model="dashForm.deptPrefix" placeholder="选填 ?dept_prefix=（前缀匹配）" clearable style="width: 200px" />
          </el-form-item>
          <el-form-item>
            <el-button type="primary" :loading="dashLoading" @click="loadDashboard">加载</el-button>
          </el-form-item>
        </el-form>
        <template v-if="dashboard">
          <div class="dash-total">工单总数 <b>{{ dashboard.total }}</b></div>
          <h4 class="dept-title">SLA 健康度</h4>
          <StatBars :items="slaBars" />
          <h4 class="dept-title">按状态</h4>
          <StatBars :items="stateBars" />
          <h4 class="dept-title">按严重性</h4>
          <StatBars :items="sevBars" />
        </template>
        <el-empty v-else description="点击加载查看看板" />
        <template v-if="deptRows.length">
          <h4 class="dept-title">一级部门分布</h4>
          <el-table :data="deptRows" size="small" border>
            <el-table-column prop="dept" label="一级部门" min-width="140" />
            <el-table-column prop="total" label="漏洞总数" width="100" />
            <el-table-column prop="open" label="未闭环" width="100" />
            <el-table-column prop="closed" label="已闭环/忽略" width="120" />
            <el-table-column label="逾期" width="100">
              <template #default="{ row }">
                <el-tag :type="row.overdue > 0 ? 'danger' : 'success'" size="small">{{ row.overdue }}</el-tag>
              </template>
            </el-table-column>
          </el-table>
        </template>
      </el-card>

      <el-alert
        v-if="integrationsError"
        :title="integrationsError"
        type="warning"
        show-icon
        :closable="false"
        style="margin-top: 12px"
      />

      <el-card header="企业邮箱 SMTP" style="margin-top: 12px" v-loading="integrationsLoading">
        <el-descriptions v-if="!integrationsReady && notify" :column="2" border>
          <el-descriptions-item label="总开关">{{ notify.enabled ? '开' : '关' }}</el-descriptions-item>
          <el-descriptions-item label="可用">
            <el-tag :type="notify.configured ? 'success' : 'danger'">{{ notify.configured ? '已就绪' : '未配置' }}</el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="服务器">{{ notify.host || '-' }}:{{ notify.port }}</el-descriptions-item>
          <el-descriptions-item label="发件人">{{ notify.from || '-' }}</el-descriptions-item>
          <el-descriptions-item label="加密">{{ notify.use_ssl ? 'SSL' : notify.use_tls ? 'TLS' : '无' }}</el-descriptions-item>
          <el-descriptions-item label="说明">SMTP 账号密码放后端 env，页面永不展示</el-descriptions-item>
        </el-descriptions>
        <template v-if="integrationsReady">
          <el-descriptions :column="2" border>
            <el-descriptions-item
              v-for="key in SMTP_KEYS"
              :key="key"
              :label="labelFor(key, key)"
            >
              <el-tag v-if="isSecret(key)" :type="isConfigured(key) ? 'success' : 'info'" size="small">
                {{ isConfigured(key) ? '已设置' : '未设置' }}
              </el-tag>
              <span v-else>{{ displayValue(key) }}</span>
            </el-descriptions-item>
          </el-descriptions>
          <el-form :model="smtpForm" label-width="110px" style="margin-top: 12px" @submit.prevent>
            <el-form-item :label="labelFor('smtp.enabled', '总开关')">
              <el-switch v-model="smtpForm.enabled" />
            </el-form-item>
            <el-form-item :label="labelFor('smtp.host', 'SMTP 服务器')">
              <el-input v-model="smtpForm.host" placeholder="smtp.company.com" clearable style="width: 260px" />
            </el-form-item>
            <el-form-item :label="labelFor('smtp.port', '端口')">
              <el-input-number v-model="smtpForm.port" :min="1" :max="65535" />
            </el-form-item>
            <el-form-item :label="labelFor('smtp.user', '账号')">
              <el-input v-model="smtpForm.user" placeholder="SMTP 登录账号" clearable style="width: 260px" />
            </el-form-item>
            <el-form-item :label="labelFor('smtp.password', '密码')">
              <el-input
                v-model="smtpForm.password"
                type="password"
                show-password
                placeholder="已设置，留空=不修改"
                clearable
                style="width: 260px"
              />
            </el-form-item>
            <el-form-item :label="labelFor('smtp.use_ssl', 'SSL')">
              <el-switch v-model="smtpForm.use_ssl" />
            </el-form-item>
            <el-form-item :label="labelFor('smtp.use_tls', 'TLS')">
              <el-switch v-model="smtpForm.use_tls" />
            </el-form-item>
            <el-form-item :label="labelFor('smtp.from', '发件人')">
              <el-input v-model="smtpForm.from" placeholder="发件人邮箱地址" clearable style="width: 260px" />
            </el-form-item>
            <el-form-item :label="labelFor('smtp.subject_prefix', '主题前缀')">
              <el-input v-model="smtpForm.subject_prefix" placeholder="【漏洞工单】" clearable style="width: 260px" />
            </el-form-item>
            <el-form-item>
              <el-button type="primary" :loading="smtpSaving" @click="onSaveSmtp">保存</el-button>
            </el-form-item>
          </el-form>
        </template>
        <el-form inline style="margin-top: 12px" @submit.prevent>
          <el-form-item label="测试收件">
            <el-input v-model="testMail" placeholder="收件人邮箱地址" clearable style="width: 220px" />
          </el-form-item>
          <el-form-item>
            <el-button type="primary" :loading="testLoading" @click="onTestMail">发送测试邮件</el-button>
          </el-form-item>
        </el-form>
        <el-alert
          v-if="smtpTestDetail"
          :title="smtpTestDetail"
          :type="smtpTestOk ? 'success' : 'error'"
          show-icon
          :closable="false"
          style="margin-top: 8px"
        />
        <p class="muted">SMTP 配在后端集成接口（smtp.*），密钥字段留空即不修改，页面永不回显密钥。</p>
      </el-card>

      <el-card header="企微扫码登录" style="margin-top: 12px" v-loading="integrationsLoading">
        <template v-if="integrationsReady">
          <el-form :model="wecomLoginForm" label-width="110px" @submit.prevent>
            <el-form-item :label="labelFor('wecom.login_corpid', '企业 CorpID')">
              <el-input v-model="wecomLoginForm.corpid" placeholder="wwxxxxxxxx" clearable style="width: 280px" />
              <el-tag
                :type="isConfigured('wecom.login_corpid') ? 'success' : 'info'"
                size="small"
                style="margin-left: 8px"
              >
                {{ isConfigured('wecom.login_corpid') ? '已设置' : '未设置' }}
              </el-tag>
            </el-form-item>
            <el-form-item :label="labelFor('wecom.login_secret', 'Secret')">
              <el-input
                v-model="wecomLoginForm.secret"
                type="password"
                show-password
                placeholder="已设置，留空=不修改"
                clearable
                style="width: 280px"
              />
              <el-tag
                :type="isConfigured('wecom.login_secret') ? 'success' : 'info'"
                size="small"
                style="margin-left: 8px"
              >
                {{ isConfigured('wecom.login_secret') ? '已设置' : '未设置' }}
              </el-tag>
            </el-form-item>
            <el-form-item>
              <el-button type="primary" :loading="wecomLoginSaving" @click="onSaveWecomLogin">保存</el-button>
              <el-button :loading="wecomLoginTestLoading" @click="onTestWecomLogin">验证连接</el-button>
            </el-form-item>
          </el-form>
          <el-alert
            v-if="wecomLoginTestDetail"
            :title="wecomLoginTestDetail"
            :type="wecomLoginTestOk ? 'success' : 'error'"
            show-icon
            :closable="false"
            style="margin-top: 8px"
          />
        </template>
        <el-alert v-else title="后端集成接口未就绪，企微登录配置暂不可编辑" type="info" show-icon :closable="false" />
        <el-descriptions title="前端构建变量（只读说明）" :column="1" border style="margin-top: 12px">
          <el-descriptions-item label="VITE_WECOM_CORPID">
            <span class="mono">VITE_WECOM_CORPID</span> —— 扫码登录 CorpID（构建时写入，页面无法修改）
          </el-descriptions-item>
          <el-descriptions-item label="VITE_WECOM_AGENTID">
            <span class="mono">VITE_WECOM_AGENTID</span> —— 自建应用 AgentID（构建时写入，页面无法修改）
          </el-descriptions-item>
          <el-descriptions-item label="二维码 URL 形状">
            <span class="mono">https://open.work.weixin.qq.com/wwopen/sso/qrConnect?appid= CORPID&agentid=AGENTID&redirect_uri=来源/login&state=vuln_login</span>
            <span>（Login.vue qrConnect iframe 在构建时拼接，改变量后需重新构建前端）</span>
          </el-descriptions-item>
        </el-descriptions>
      </el-card>

      <el-card header="企微群机器人（Webhook）" style="margin-top: 12px" v-loading="integrationsLoading">
        <el-descriptions :column="2" border>
          <el-descriptions-item label="可用">
            <el-tag :type="botConfigured ? 'success' : 'info'">
              {{ botConfigured ? '已就绪' : '未配置' }}
            </el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="地址">
            {{ botConfigured ? '已配置（页面不展示明文）' : fallbackWebhookText }}
          </el-descriptions-item>
        </el-descriptions>
        <template v-if="integrationsReady">
          <el-form :model="wecomBotForm" label-width="110px" style="margin-top: 12px" @submit.prevent>
            <el-form-item :label="labelFor('wecom.bot_webhook', 'Webhook')">
              <el-input
                v-model="wecomBotForm.webhook"
                type="password"
                show-password
                placeholder="已设置，留空=不修改"
                clearable
                style="width: 320px"
              />
            </el-form-item>
            <el-form-item>
              <el-button type="primary" :loading="wecomBotSaving" @click="onSaveWecomBot">保存</el-button>
            </el-form-item>
          </el-form>
        </template>
        <el-form inline style="margin-top: 12px" @submit.prevent>
          <el-form-item>
            <el-button type="primary" :loading="wecomTestLoading" @click="onTestWecom">发送群测试消息</el-button>
          </el-form-item>
        </el-form>
        <el-alert
          v-if="wecomBotTestDetail"
          :title="wecomBotTestDetail"
          :type="wecomBotTestOk ? 'success' : 'error'"
          show-icon
          :closable="false"
          style="margin-top: 8px"
        />
        <p class="muted">SLA 升级时自动推送群消息；密钥字段留空即不修改。</p>
      </el-card>

      <el-card header="CMDB 对接" style="margin-top: 12px" v-loading="integrationsLoading">
        <template v-if="integrationsReady">
          <el-form :model="cmdbForm" label-width="110px" @submit.prevent>
            <el-form-item :label="labelFor('cmdb.base_url', '服务地址')">
              <el-input v-model="cmdbForm.base_url" placeholder="https://cmdb.company.com" clearable style="width: 320px" />
              <el-tag
                :type="isConfigured('cmdb.base_url') ? 'success' : 'info'"
                size="small"
                style="margin-left: 8px"
              >
                {{ isConfigured('cmdb.base_url') ? '已设置' : '未设置' }}
              </el-tag>
            </el-form-item>
            <el-form-item :label="labelFor('cmdb.token', 'Token')">
              <el-input
                v-model="cmdbForm.token"
                type="password"
                show-password
                placeholder="已设置，留空=不修改"
                clearable
                style="width: 320px"
              />
              <el-tag
                :type="isConfigured('cmdb.token') ? 'success' : 'info'"
                size="small"
                style="margin-left: 8px"
              >
                {{ isConfigured('cmdb.token') ? '已设置' : '未设置' }}
              </el-tag>
            </el-form-item>
            <el-form-item>
              <el-button type="primary" :loading="cmdbSaving" @click="onSaveCmdb">保存</el-button>
              <el-button :loading="cmdbTestLoading" @click="onTestCmdb">测试连接</el-button>
              <el-button type="success" :loading="cmdbSyncLoading" @click="onCmdbSync">立即同步</el-button>
            </el-form-item>
          </el-form>
          <el-alert
            v-if="cmdbTestDetail"
            :title="cmdbTestDetail"
            :type="cmdbTestOk ? 'success' : 'error'"
            show-icon
            :closable="false"
            style="margin-top: 8px"
          />
          <el-alert
            v-if="cmdbSyncDetail"
            :title="cmdbSyncDetail"
            :type="cmdbSyncOk ? 'success' : 'error'"
            show-icon
            :closable="false"
            style="margin-top: 8px"
          />
        </template>
        <el-alert v-else title="后端集成接口未就绪，CMDB 配置暂不可编辑" type="info" show-icon :closable="false" />
      </el-card>

      <el-card header="报告接入 FTP / Watcher（只读说明）" style="margin-top: 12px">
        <el-descriptions :column="1" border>
          <el-descriptions-item label="FTP_USER">报告 FTP 账号（deploy/.env 配置）</el-descriptions-item>
          <el-descriptions-item label="FTP_PASS">报告 FTP 密码（deploy/.env 配置）</el-descriptions-item>
          <el-descriptions-item label="PASV_ADDRESS">FTP 被动模式外网地址（deploy/.env 配置）</el-descriptions-item>
          <el-descriptions-item label="WATCHER_TOKEN">Watcher 回调鉴权 Token（deploy/.env 配置）</el-descriptions-item>
          <el-descriptions-item label="WATCHER_POLL_INTERVAL">Watcher 轮询间隔秒数（deploy/.env 配置）</el-descriptions-item>
          <el-descriptions-item label="WATCHER_PATTERN">Watcher 监听文件名模式（deploy/.env 配置）</el-descriptions-item>
          <el-descriptions-item label="WATCHER_DRY_RUN">Watcher 试运行开关（deploy/.env 配置）</el-descriptions-item>
        </el-descriptions>
        <p class="muted">watcher 是独立容器，只读 env，改后重启 watcher 生效。本卡仅展示，不调用任何接口。</p>
      </el-card>

      <el-card header="字段映射查看器（GET /api/imports/field-map）" style="margin-top: 12px" v-loading="fieldMapLoading">
        <template v-if="fieldMap">
          <el-tag type="success" size="small">版本 {{ fieldMap.version ?? '未知' }}</el-tag>
          <el-input
            :model-value="fieldMapPretty"
            type="textarea"
            autosize
            readonly
            class="mono-input"
            style="margin-top: 8px"
          />
        </template>
        <el-alert
          v-else-if="fieldMapError"
          :title="fieldMapError"
          type="warning"
          show-icon
          :closable="false"
        />
        <el-empty v-else description="暂无字段映射数据" />
      </el-card>
    </el-main>
  </el-container>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import {
  fetchDashboard,
  fetchNotifyStatus,
  fetchSlaPolicies,
  updateSlaPolicy,
  type DashboardData,
  type DeptBucket,
  type NotifyStatus,
  type SlaPolicyRow,
} from '../api/dashboard'
import {
  fetchFieldMap,
  fetchIntegrations,
  testIntegration,
  triggerCmdbSync,
  updateIntegrationKey,
  type FieldMapResponse,
  type IntegrationGroup,
  type IntegrationTestKey,
} from '../api/integrations'
import StatBars, { type StatBarItem } from '../components/StatBars.vue'

const slaRows = ref<SlaPolicyRow[]>([])
const slaLoading = ref(false)
const slaSaving = ref('')

async function loadSla() {
  slaLoading.value = true
  try {
    slaRows.value = await fetchSlaPolicies()
  } catch (e: unknown) {
    const err = e as { response?: { data?: { detail?: string } } }
    ElMessage.error(err.response?.data?.detail ?? '加载SLA策略失败')
  } finally {
    slaLoading.value = false
  }
}

async function onSaveSla(row: SlaPolicyRow) {
  slaSaving.value = row.severity
  try {
    const saved = await updateSlaPolicy(row.severity, row.days, row.warn_days_before)
    Object.assign(row, saved)
    ElMessage.success(`已保存：${row.severity} ${row.days} 天`)
  } catch (e: unknown) {
    const err = e as { response?: { data?: { detail?: string } } }
    ElMessage.error(err.response?.data?.detail ?? '保存失败')
  } finally {
    slaSaving.value = ''
  }
}

const dashForm = reactive({ dept: '', deptPrefix: '' })
const dashboard = ref<DashboardData | null>(null)
const dashLoading = ref(false)

const deptRows = computed<Array<DeptBucket & { dept: string }>>(() => {
  const byDept = dashboard.value?.by_dept ?? {}
  return Object.entries(byDept).map(([dept, bucket]) => ({ dept, ...bucket }))
})

const slaBars = computed<StatBarItem[]>(() => {
  const s = dashboard.value?.sla
  if (!s) return []
  return [
    { label: '逾期', value: s.overdue, tone: 'danger' },
    { label: '预警（3天内）', value: s.at_risk, tone: 'warning' },
    { label: '正常', value: s.ok, tone: 'success' },
    { label: '无SLA', value: s.no_due, tone: 'info' },
  ]
})

const stateBars = computed<StatBarItem[]>(() => {
  const byState = dashboard.value?.by_state ?? {}
  const tones: Record<string, StatBarItem['tone']> = {
    '已闭合': 'success',
    '已忽略': 'info',
    '已延期': 'warning',
    '待复测': 'warning',
  }
  return Object.entries(byState).map(([label, value]) => ({ label, value, tone: tones[label] ?? 'default' }))
})

const sevBars = computed<StatBarItem[]>(() => {
  const bySev = dashboard.value?.by_severity ?? {}
  const tones: Record<string, StatBarItem['tone']> = {
    '严重': 'danger',
    '高': 'warning',
    '中': 'info',
    '低': 'success',
  }
  return Object.entries(bySev).map(([label, value]) => ({ label, value, tone: tones[label] ?? 'default' }))
})

const fallbackWebhookText = 'https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=****'

const notify = ref<NotifyStatus | null>(null)
const testMail = ref('')
const testLoading = ref(false)

async function loadNotify() {
  try {
    notify.value = await fetchNotifyStatus()
  } catch {
    notify.value = null
  }
}

// ---- 集成中心（GET /api/ops/integrations，secret 字段永不回显明文） ----
const SMTP_KEYS = [
  'smtp.enabled',
  'smtp.host',
  'smtp.port',
  'smtp.user',
  'smtp.password',
  'smtp.use_ssl',
  'smtp.use_tls',
  'smtp.from',
  'smtp.subject_prefix',
]
const WECOM_LOGIN_KEYS = ['wecom.login_corpid', 'wecom.login_secret']
const WECOM_BOT_KEYS = ['wecom.bot_webhook']
const CMDB_KEYS = ['cmdb.base_url', 'cmdb.token']

const integrationGroups = ref<IntegrationGroup[]>([])
const integrationsLoading = ref(false)
const integrationsReady = ref(false)
const integrationsError = ref('')

const smtpForm = reactive({
  enabled: false,
  host: '',
  port: 25,
  user: '',
  password: '',
  use_ssl: false,
  use_tls: false,
  from: '',
  subject_prefix: '',
})
const wecomLoginForm = reactive({ corpid: '', secret: '' })
const wecomBotForm = reactive({ webhook: '' })
const cmdbForm = reactive({ base_url: '', token: '' })

const smtpSaving = ref(false)
const wecomLoginSaving = ref(false)
const wecomBotSaving = ref(false)
const cmdbSaving = ref(false)

const smtpTestOk = ref(false)
const smtpTestDetail = ref('')
const wecomLoginTestLoading = ref(false)
const wecomLoginTestOk = ref(false)
const wecomLoginTestDetail = ref('')
const wecomBotTestOk = ref(false)
const wecomBotTestDetail = ref('')
const cmdbTestLoading = ref(false)
const cmdbTestOk = ref(false)
const cmdbTestDetail = ref('')
const cmdbSyncLoading = ref(false)
const cmdbSyncOk = ref(false)
const cmdbSyncDetail = ref('')

function findField(key: string) {
  for (const group of integrationGroups.value) {
    const field = group.fields?.find((f) => f.key === key)
    if (field) return field
  }
  return undefined
}

function labelFor(key: string, fallback: string): string {
  return findField(key)?.label || fallback
}

function isSecret(key: string): boolean {
  return findField(key)?.secret ?? false
}

function isConfigured(key: string): boolean {
  return findField(key)?.configured ?? false
}

function displayValue(key: string): string {
  const field = findField(key)
  const value = field?.value
  if (value == null || value === '') return field?.hint || '-'
  if (typeof value === 'boolean') return value ? '开' : '关'
  return String(value)
}

const botConfigured = computed<boolean>(() => {
  if (integrationsReady.value) return isConfigured('wecom.bot_webhook')
  return notify.value?.wecom_configured ?? false
})

function syncFormsFromApi() {
  const plain = (key: string): string => {
    const value = findField(key)?.value
    return typeof value === 'string' ? value : ''
  }
  const flag = (key: string): boolean => findField(key)?.value === true
  const portRaw = findField('smtp.port')?.value
  smtpForm.enabled = flag('smtp.enabled')
  smtpForm.host = plain('smtp.host')
  smtpForm.port = typeof portRaw === 'number' ? portRaw : Number(portRaw) || 25
  smtpForm.user = plain('smtp.user')
  smtpForm.password = ''
  smtpForm.use_ssl = flag('smtp.use_ssl')
  smtpForm.use_tls = flag('smtp.use_tls')
  smtpForm.from = plain('smtp.from')
  smtpForm.subject_prefix = plain('smtp.subject_prefix')
  wecomLoginForm.corpid = plain('wecom.login_corpid')
  wecomLoginForm.secret = ''
  wecomBotForm.webhook = ''
  cmdbForm.base_url = plain('cmdb.base_url')
  cmdbForm.token = ''
}

function secretValue(key: string, input: string): string | undefined {
  if ((findField(key)?.secret ?? false) && input === '') return undefined
  return input
}

async function saveKeys(keys: string[], values: Record<string, string | number | boolean>): Promise<boolean> {
  for (const key of keys) {
    const raw = values[key]
    const value = typeof raw === 'string' ? secretValue(key, raw) : raw
    if (value === undefined) continue
    await updateIntegrationKey(key, value)
  }
  return true
}

function refreshError(e: unknown, fallback: string): string {
  const err = e as { response?: { status?: number; data?: { detail?: string } } }
  return err.response?.data?.detail ?? fallback
}

async function loadIntegrations() {
  integrationsLoading.value = true
  integrationsError.value = ''
  try {
    integrationGroups.value = await fetchIntegrations()
    integrationsReady.value = true
    syncFormsFromApi()
  } catch (e: unknown) {
    const err = e as { response?: { status?: number } }
    integrationsReady.value = false
    integrationsError.value =
      err.response?.status === 404
        ? '后端集成接口未就绪（GET /api/ops/integrations 404），下方为只读兜底状态，可编辑功能待后端部署后使用。'
        : '加载集成配置失败，请稍后重试。'
  } finally {
    integrationsLoading.value = false
  }
}

async function onSaveSmtp() {
  smtpSaving.value = true
  try {
    await saveKeys(SMTP_KEYS, {
      'smtp.enabled': smtpForm.enabled,
      'smtp.host': smtpForm.host,
      'smtp.port': smtpForm.port,
      'smtp.user': smtpForm.user,
      'smtp.password': smtpForm.password,
      'smtp.use_ssl': smtpForm.use_ssl,
      'smtp.use_tls': smtpForm.use_tls,
      'smtp.from': smtpForm.from,
      'smtp.subject_prefix': smtpForm.subject_prefix,
    })
    await loadIntegrations()
    ElMessage.success('SMTP 配置已保存')
  } catch (e: unknown) {
    ElMessage.error(refreshError(e, '保存失败'))
  } finally {
    smtpSaving.value = false
  }
}

async function runIntegrationTest(
  key: IntegrationTestKey,
  to: string | undefined,
  setOk: (v: boolean) => void,
  setDetail: (v: string) => void,
  emptyToHint: string,
): Promise<void> {
  if (to !== undefined && !to.trim()) {
    ElMessage.warning(emptyToHint)
    return
  }
  try {
    const res = await testIntegration(key, to?.trim() || undefined)
    setOk(res.ok)
    setDetail(res.detail || (res.ok ? '连接正常' : '连接失败'))
    if (res.ok) ElMessage.success('连接验证通过')
    else ElMessage.warning(res.detail || '连接验证未通过')
  } catch (e: unknown) {
    setOk(false)
    const detail = refreshError(e, '连接验证失败')
    setDetail(detail)
    ElMessage.error(detail)
  }
}

async function onTestMail() {
  testLoading.value = true
  try {
    await runIntegrationTest(
      'smtp',
      testMail.value,
      (v) => { smtpTestOk.value = v },
      (v) => { smtpTestDetail.value = v },
      '请填写测试收件邮箱',
    )
  } finally {
    testLoading.value = false
  }
}

async function onSaveWecomLogin() {
  wecomLoginSaving.value = true
  try {
    await saveKeys(WECOM_LOGIN_KEYS, {
      'wecom.login_corpid': wecomLoginForm.corpid,
      'wecom.login_secret': wecomLoginForm.secret,
    })
    await loadIntegrations()
    ElMessage.success('企微扫码登录配置已保存')
  } catch (e: unknown) {
    ElMessage.error(refreshError(e, '保存失败'))
  } finally {
    wecomLoginSaving.value = false
  }
}

async function onTestWecomLogin() {
  wecomLoginTestLoading.value = true
  try {
    await runIntegrationTest(
      'wecom.login',
      undefined,
      (v) => { wecomLoginTestOk.value = v },
      (v) => { wecomLoginTestDetail.value = v },
      '',
    )
  } finally {
    wecomLoginTestLoading.value = false
  }
}

async function onSaveWecomBot() {
  wecomBotSaving.value = true
  try {
    await saveKeys(WECOM_BOT_KEYS, { 'wecom.bot_webhook': wecomBotForm.webhook })
    await loadIntegrations()
    ElMessage.success('群机器人配置已保存')
  } catch (e: unknown) {
    ElMessage.error(refreshError(e, '保存失败'))
  } finally {
    wecomBotSaving.value = false
  }
}

const wecomTestLoading = ref(false)

async function onTestWecom() {
  wecomTestLoading.value = true
  try {
    await runIntegrationTest(
      'wecom.bot',
      undefined,
      (v) => { wecomBotTestOk.value = v },
      (v) => { wecomBotTestDetail.value = v },
      '',
    )
  } finally {
    wecomTestLoading.value = false
  }
}

async function onSaveCmdb() {
  cmdbSaving.value = true
  try {
    await saveKeys(CMDB_KEYS, {
      'cmdb.base_url': cmdbForm.base_url,
      'cmdb.token': cmdbForm.token,
    })
    await loadIntegrations()
    ElMessage.success('CMDB 配置已保存')
  } catch (e: unknown) {
    ElMessage.error(refreshError(e, '保存失败'))
  } finally {
    cmdbSaving.value = false
  }
}

async function onTestCmdb() {
  cmdbTestLoading.value = true
  try {
    await runIntegrationTest(
      'cmdb',
      undefined,
      (v) => { cmdbTestOk.value = v },
      (v) => { cmdbTestDetail.value = v },
      '',
    )
  } finally {
    cmdbTestLoading.value = false
  }
}

async function onCmdbSync() {
  cmdbSyncLoading.value = true
  cmdbSyncDetail.value = ''
  try {
    const res = await triggerCmdbSync()
    cmdbSyncOk.value = true
    cmdbSyncDetail.value = `同步完成：新增/更新 ${res.upserted ?? 0}，重映射 ${res.remapped ?? 0}，无主 ${res.orphaned ?? 0}`
    ElMessage.success('CMDB 同步完成')
  } catch (e: unknown) {
    cmdbSyncOk.value = false
    const detail = refreshError(e, 'CMDB 同步失败')
    cmdbSyncDetail.value = detail
    ElMessage.error(detail)
  } finally {
    cmdbSyncLoading.value = false
  }
}

// ---- 字段映射查看器（GET /api/imports/field-map） ----
const fieldMap = ref<FieldMapResponse | null>(null)
const fieldMapLoading = ref(false)
const fieldMapError = ref('')

const fieldMapPretty = computed<string>(() => {
  if (!fieldMap.value) return ''
  const { version: _version, ...rest } = fieldMap.value
  void _version
  return JSON.stringify(rest, null, 2)
})

async function loadFieldMap() {
  fieldMapLoading.value = true
  fieldMapError.value = ''
  try {
    fieldMap.value = await fetchFieldMap()
  } catch (e: unknown) {
    fieldMap.value = null
    fieldMapError.value = refreshError(e, '字段映射接口请求失败。')
  } finally {
    fieldMapLoading.value = false
  }
}

async function loadDashboard() {
  dashLoading.value = true
  try {
    dashboard.value = await fetchDashboard({
      dept: dashForm.dept.trim() || undefined,
      dept_prefix: dashForm.deptPrefix.trim() || undefined,
    })
  } catch (e: unknown) {
    const err = e as { response?: { data?: { friendly?: string; detail?: string } } }
    ElMessage.error(err.response?.data?.friendly ?? err.response?.data?.detail ?? '加载看板失败')
  } finally {
    dashLoading.value = false
  }
}

onMounted(() => {
  void loadDashboard()
  void loadNotify()
  void loadSla()
  void loadIntegrations()
  void loadFieldMap()
})
</script>

<style scoped>
.bar {
  display: flex;
  align-items: center;
  gap: 12px;
}
.muted {
  color: #999;
  font-size: 12px;
}
.dept-title {
  margin: 14px 0 8px;
}
.dash-total {
  font-size: 15px;
  color: #606266;
}
.dash-total b {
  font-size: 26px;
  color: #303133;
  margin-left: 6px;
}
.mono {
  font-family: monospace;
  font-size: 12px;
  white-space: pre-wrap;
  word-break: break-all;
}
.mono-input :deep(textarea) {
  font-family: monospace;
  font-size: 12px;
}
</style>
