<template>
  <el-container>
    <el-header class="bar">
      <el-button link @click="$router.back()">← 返回</el-button>
      <span>工单详情 #{{ id }}</span>
    </el-header>
    <el-main v-loading="loading">
      <el-card v-if="ticket" header="漏洞信息">
        <el-descriptions :column="2" border>
          <el-descriptions-item label="标题">{{ ticket.title }}</el-descriptions-item>
          <el-descriptions-item label="IP/端口">{{ ticket.ip }}:{{ ticket.port ?? '-' }}</el-descriptions-item>
          <el-descriptions-item label="严重性">
            <SeverityTag :severity="String(ticket.severity ?? '')" />
          </el-descriptions-item>
          <el-descriptions-item label="状态">
            <StateTag :state="String(ticket.state ?? '')" />
          </el-descriptions-item>
          <el-descriptions-item label="SLA">
            <SlaTag :sla-due-at="ticket.sla_due_at ?? null" />
          </el-descriptions-item>
          <el-descriptions-item label="负责人">{{ ticket.assignee ?? '-' }}</el-descriptions-item>
          <el-descriptions-item label="发现日期">{{ String(ticket.first_seen_at ?? '').slice(0, 10) || '-' }}</el-descriptions-item>
          <el-descriptions-item label="来源">{{ String(ticket.source ?? '-') }}</el-descriptions-item>
          <el-descriptions-item label="CVE">{{ String(ticket.cve ?? '-') }}</el-descriptions-item>
          <el-descriptions-item label="插件">{{ String(ticket.plugin_name ?? ticket.plugin_id ?? '-') }}</el-descriptions-item>
          <el-descriptions-item label="协议/服务"
            >{{ String(ticket.protocol ?? '-') }} / {{ String(ticket.service ?? '-') }}</el-descriptions-item
          >
          <el-descriptions-item label="CVSS">{{ String(ticket.cvss ?? '-') }}</el-descriptions-item>
        </el-descriptions>
        <div class="actions">
          <el-button type="primary" @click="evidenceOpen = true">提交修复证据</el-button>
          <el-button @click="delayOpen = true">申请延期</el-button>
          <!-- resume = re-submit evidence after 已延期; backend transition 已延期→待修复 via submit -->
          <el-button v-if="ticket.state === '已延期'" type="success" @click="evidenceOpen = true">
            恢复推进（重新提交证据）
          </el-button>
        </div>
      </el-card>

      <el-card header="漏洞详情" style="margin-top: 12px">
        <div v-if="String(ticket?.description ?? '').trim()" class="prewrap">{{ String(ticket?.description) }}</div>
        <el-empty v-else description="暂无漏洞描述" />
      </el-card>

      <el-card header="修复建议" style="margin-top: 12px">
        <div v-if="String(ticket?.solution ?? '').trim()" class="prewrap">{{ String(ticket?.solution) }}</div>
        <el-empty v-else description="暂无修复建议" />
      </el-card>

      <el-card header="修复证据图片" style="margin-top: 12px">
        <div v-if="(ticket?.attachments ?? []).length" class="thumbs">
          <el-image
            v-for="a in ticket?.attachments ?? []"
            :key="a.id"
            :src="String(a.url)"
            :preview-src-list="(ticket?.attachments ?? []).map((x) => String(x.url))"
            fit="cover"
            class="thumb"
          />
        </div>
        <el-empty v-else description="暂无图片" />
      </el-card>

      <el-card header="修复证据时间线" style="margin-top: 12px">
        <el-timeline v-if="evidenceEntries.length">
          <el-timeline-item
            v-for="(e, i) in evidenceEntries"
            :key="i"
            :timestamp="e.created_at || ''"
          >
            {{ e.content }} <span v-if="e.author" class="muted">— {{ e.author }}</span>
          </el-timeline-item>
        </el-timeline>
        <el-empty v-else description="暂无修复证据" />
      </el-card>

      <el-card header="审计时间线" style="margin-top: 12px">
        <el-timeline v-if="(ticket?.audit ?? []).length">
          <el-timeline-item
            v-for="a in ticket?.audit ?? []"
            :key="a.id"
            :timestamp="String(a.created_at ?? '')"
          >
            [{{ timelineAction(a) }}] {{ timelineDetail(a) }}
            <span class="muted" v-if="a.actor">— {{ a.actor }}</span>
          </el-timeline-item>
        </el-timeline>
        <el-empty v-else description="暂无审计记录" />
      </el-card>

      <el-dialog v-model="evidenceOpen" title="提交修复证据">
        <el-input v-model="evidenceText" type="textarea" :rows="4" placeholder="描述修复动作/补丁/验证结果" />
        <el-upload
          :http-request="onPickImage"
          :show-file-list="false"
          accept="image/png,image/jpeg,image/gif,image/webp"
          style="margin-top: 12px"
        >
          <el-button>添加图片（png/jpg/gif/webp，≤5MB）</el-button>
        </el-upload>
        <div v-if="pendingImages.length" class="thumbs" style="margin-top: 8px">
          <div v-for="a in pendingImages" :key="a.id" class="thumb-wrap">
            <el-image :src="String(a.url)" fit="cover" class="thumb" />
            <el-button link type="danger" @click="removePendingImage(a.id)">移除</el-button>
          </div>
        </div>
        <template #footer>
          <el-button @click="evidenceOpen = false">取消</el-button>
          <el-button type="primary" :loading="submitting" @click="onSubmitEvidence">提交</el-button>
        </template>
      </el-dialog>

      <el-dialog v-model="delayOpen" title="申请延期">
        <el-form :model="delayForm" label-width="90px">
          <el-form-item label="延期天数">
            <el-input-number v-model="delayForm.delay_days" :min="1" :max="180" />
          </el-form-item>
          <el-form-item label="延期至">
            <el-date-picker v-model="delayForm.delay_until" type="date" placeholder="或选日期" clearable />
          </el-form-item>
          <el-form-item label="原因">
            <el-input v-model="delayForm.reason" type="textarea" :rows="3" placeholder="必填：延期原因" />
          </el-form-item>
        </el-form>
        <p class="muted">提交后进入待审批，运营（或负责人≤30天）审批通过才生效。</p>
        <template #footer>
          <el-button @click="delayOpen = false">取消</el-button>
          <el-button type="primary" :loading="submitting" @click="onRequestDelay">提交</el-button>
        </template>
      </el-dialog>
    </el-main>
  </el-container>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { useRoute } from 'vue-router'
import { ElMessage } from 'element-plus'
import type { UploadRequestOptions } from 'element-plus'
import SlaTag from '../components/SlaTag.vue'
import StateTag from '../components/StateTag.vue'
import SeverityTag from '../components/SeverityTag.vue'
import {
  fetchTicketDetail,
  requestDelay,
  submitEvidence,
  toEvidenceEntries,
  uploadAttachment,
  type Attachment,
  type TicketDetail,
  type TimelineRow,
} from '../api/tickets'

const route = useRoute()
const id = String(route.params.id ?? '')

const ticket = ref<TicketDetail | null>(null)
const evidenceEntries = computed(() => toEvidenceEntries(ticket.value?.fix_evidence))
const loading = ref(false)
const submitting = ref(false)
const evidenceOpen = ref(false)
const delayOpen = ref(false)
const evidenceText = ref('')
const pendingImages = ref<Attachment[]>([])

async function onPickImage(options: UploadRequestOptions) {
  try {
    const saved = await uploadAttachment(id, options.file)
    pendingImages.value.push(saved)
  } catch (e: unknown) {
    const err = e as { response?: { data?: { detail?: string } } }
    ElMessage.error(err.response?.data?.detail ?? '图片上传失败')
  }
}

function removePendingImage(attachmentId: string | number) {
  pendingImages.value = pendingImages.value.filter((a) => a.id !== attachmentId)
}

const ACTION_LABELS: Record<string, string> = {
  'ticket.create': '创建',
  'ticket.update': '更新',
  'ticket.transition': '流转',
  'user.create': '建号',
  'user.reset_password': '重置密码',
  'user.deactivate': '停用用户',
}

function timelineAction(a: TimelineRow): string {
  const raw = String(a.action ?? '')
  if (ACTION_LABELS[raw]) return ACTION_LABELS[raw]
  return raw.split('.').pop() || raw
}

function fmtTimelineVal(v: unknown): string {
  if (v == null || v === '') return '-'
  const s = typeof v === 'object' ? JSON.stringify(v) : String(v)
  return s.length > 60 ? `${s.slice(0, 60)}…` : s
}

function timelineDetail(a: TimelineRow): string {
  const d = (a.diff_json ?? {}) as Record<string, unknown>
  if (typeof d.from === 'string' && typeof d.to === 'string') return `${d.from} → ${d.to}`
  const changed = d.changed as Record<string, { old?: unknown; new?: unknown }> | undefined
  if (changed && typeof changed === 'object') {
    return Object.entries(changed)
      .map(([k, v]) => `${k}: ${fmtTimelineVal(v?.old)} → ${fmtTimelineVal(v?.new)}`)
      .join('；')
  }
  if (d.created === true) return '工单生成'
  return ''
}
const delayForm = reactive<{ delay_days?: number; delay_until?: string; reason: string }>({
  delay_days: 7,
  delay_until: undefined,
  reason: '',
})

async function load() {
  loading.value = true
  try {
    ticket.value = await fetchTicketDetail(id)
  } catch (e: unknown) {
    const err = e as { response?: { data?: { friendly?: string; detail?: string } } }
    ElMessage.error(err.response?.data?.friendly ?? err.response?.data?.detail ?? '加载详情失败')
  } finally {
    loading.value = false
  }
}

async function onSubmitEvidence() {
  if (!evidenceText.value.trim()) {
    ElMessage.warning('请填写修复证据')
    return
  }
  submitting.value = true
  try {
    await submitEvidence(
      id,
      evidenceText.value.trim(),
      pendingImages.value.map((a) => a.id),
    )
    ElMessage.success('证据已提交')
    evidenceOpen.value = false
    evidenceText.value = ''
    pendingImages.value = []
    await load()
  } catch (e: unknown) {
    const err = e as { response?: { data?: { friendly?: string; detail?: string } } }
    ElMessage.error(err.response?.data?.friendly ?? err.response?.data?.detail ?? '提交失败')
  } finally {
    submitting.value = false
  }
}

async function onRequestDelay() {
  if (!delayForm.reason.trim()) {
    ElMessage.warning('请填写延期原因')
    return
  }
  submitting.value = true
  try {
    await requestDelay(id, {
      delay_days: delayForm.delay_days,
      delay_until: delayForm.delay_until,
      reason: delayForm.reason.trim(),
    })
    ElMessage.success('延期申请已提交，待审批')
    delayOpen.value = false
    await load()
  } catch (e: unknown) {
    const err = e as { response?: { data?: { friendly?: string; detail?: string } } }
    ElMessage.error(err.response?.data?.friendly ?? err.response?.data?.detail ?? '延期申请失败')
  } finally {
    submitting.value = false
  }
}

onMounted(() => {
  void load()
})
</script>

<style scoped>
.bar {
  display: flex;
  align-items: center;
  gap: 12px;
}
.actions {
  margin-top: 12px;
  display: flex;
  gap: 8px;
}
.muted {
  color: #999;
  font-size: 12px;
}
.prewrap {
  white-space: pre-wrap;
  word-break: break-word;
  line-height: 1.7;
}
.thumbs {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}
.thumb {
  width: 96px;
  height: 96px;
  border-radius: 6px;
}
.thumb-wrap {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 4px;
}
</style>
