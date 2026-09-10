<template>
  <el-container>
    <el-header class="bar">
      <span>审计日志</span>
      <span class="user">{{ auth.user?.username }} ({{ auth.user?.role }})</span>
      <el-button link @click="$router.push('/my')">我的工单</el-button>
      <el-button v-if="showOps" @click="$router.push('/ops')">运营后台</el-button>
      <el-button link @click="onLogout">退出</el-button>
    </el-header>
    <el-main>
      <el-card>
        <el-form inline :model="filters">
          <el-form-item label="工单ID">
            <el-input v-model="filters.ticket_id" placeholder="数字ID" clearable style="width: 140px" @keyup.enter="load(1)" />
          </el-form-item>
          <el-form-item label="操作人">
            <el-input v-model="filters.actor" placeholder="用户名/ID" clearable style="width: 180px" @keyup.enter="load(1)" />
          </el-form-item>
          <el-form-item>
            <el-button type="primary" @click="load(1)">查询</el-button>
          </el-form-item>
        </el-form>

        <el-table :data="rows" v-loading="loading" style="width: 100%">
          <el-table-column prop="created_at" label="时间" width="170">
            <template #default="{ row }">{{ String(row.created_at ?? '—').slice(0, 19).replace('T', ' ') }}</template>
          </el-table-column>
          <el-table-column prop="action" label="动作" width="180" />
          <el-table-column prop="actor" label="操作人" width="130">
            <template #default="{ row }">{{ String(row.actor ?? '系统') }}</template>
          </el-table-column>
          <el-table-column prop="ticket_id" label="工单" width="110">
            <template #default="{ row }">
              <router-link v-if="row.ticket_id != null" :to="`/my/${row.ticket_id}`">#{{ row.ticket_id }}</router-link>
              <span v-else>—</span>
            </template>
          </el-table-column>
          <el-table-column prop="entity" label="对象" width="120">
            <template #default="{ row }">{{ String(row.entity ?? '—') }}</template>
          </el-table-column>
          <el-table-column label="变更" min-width="240">
            <template #default="{ row }"
              ><span class="cell-ellipsis" :title="formatDiff(row.diff_json)">{{
                formatDiff(row.diff_json)
              }}</span></template
            >
          </el-table-column>
        </el-table>
        <el-empty v-if="!loading && rows.length === 0" description="暂无审计记录" />

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
  </el-container>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { fetchAuditLogs, type AuditRow } from '../api/audit'
import { canShowAuditButton, canShowOpsButton } from '../utils/tickets'
import { useAuthStore } from '../stores/auth'

const router = useRouter()
const auth = useAuthStore()
auth.hydrate()

const filters = reactive({ ticket_id: '', actor: '' })
const rows = ref<AuditRow[]>([])
const total = ref(0)
const page = ref(1)
const pageSize = ref(20)
const loading = ref(false)

const showOps = computed(() => canShowOpsButton(auth.role))

function formatDiff(diff: AuditRow['diff_json']): string {
  if (!diff || typeof diff !== 'object') return '—'
  try {
    return JSON.stringify(diff)
  } catch {
    return '—'
  }
}

async function load(p = 1) {
  loading.value = true
  page.value = p
  try {
    const res = await fetchAuditLogs({ ...filters, page: p, page_size: pageSize.value })
    rows.value = res.results
    total.value = res.count
  } catch (e: unknown) {
    const err = e as { response?: { data?: { friendly?: string; detail?: string } } }
    ElMessage.error(err.response?.data?.friendly ?? err.response?.data?.detail ?? '加载审计日志失败')
  } finally {
    loading.value = false
  }
}

function onLogout() {
  auth.logout()
  void router.push('/login')
}

onMounted(() => {
  if (!canShowAuditButton(auth.role)) {
    void router.push('/my')
    return
  }
  void load(1)
})
</script>

<style scoped>
.bar {
  display: flex;
  align-items: center;
  gap: 12px;
}
.bar .user {
  margin-left: auto;
  color: #909399;
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
