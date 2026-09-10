<template>
  <el-container>
    <el-header class="bar">
      <span>资产映射</span>
      <el-button link @click="$router.push('/ops')">返回工单池</el-button>
    </el-header>
    <el-main>
      <el-card header="按 IP 查询现任负责人">
        <el-form inline :model="form">
          <el-form-item label="IP">
            <el-input v-model="form.ip" placeholder="如 10.0.0.1" clearable style="width: 220px" @keyup.enter="onSearch" />
          </el-form-item>
          <el-form-item>
            <el-button type="primary" :loading="loading" @click="onSearch">查询</el-button>
            <el-button @click="showOrphans = !showOrphans">{{ showOrphans ? '隐藏无主资产' : '无主资产快捷查看' }}</el-button>
            <el-button type="warning" :loading="syncing" @click="onSync">触发 CMDB 同步</el-button>
            <el-button type="success" plain @click="createDlg.open = true">新建资产</el-button>
          </el-form-item>
        </el-form>
      </el-card>

      <el-card v-if="mapping" header="现任负责人" style="margin-top: 12px">
        <el-descriptions :column="2" border>
          <el-descriptions-item label="IP">{{ mapping.ip }}</el-descriptions-item>
          <el-descriptions-item label="主机名">{{ String(mapping.hostname ?? '-') }}</el-descriptions-item>
          <el-descriptions-item label="负责人">{{ mapping.current?.username ?? '— 无主' }}</el-descriptions-item>
          <el-descriptions-item label="企微 ID">{{ mapping.current?.wecom_userid ?? '-' }}</el-descriptions-item>
          <el-descriptions-item label="任期起">{{ String(mapping.current?.valid_from ?? '-') }}</el-descriptions-item>
          <el-descriptions-item label="任期止">{{ String(mapping.current?.valid_to ?? '至今') }}</el-descriptions-item>
        </el-descriptions>
        <el-form inline style="margin-top: 12px" @submit.prevent>
          <el-form-item label="变更负责人">
            <el-input v-model="remapForm.username" placeholder="用户名，留空则置无主" clearable style="width: 200px" />
          </el-form-item>
          <el-form-item>
            <el-button type="primary" :loading="remapping" @click="onRemap">确认变更（自动重派单）</el-button>
          </el-form-item>
        </el-form>
      </el-card>

      <el-card v-if="mapping" header="映射历史时间线（valid_from/valid_to）" style="margin-top: 12px">
        <MappingHistory :history="mapping.history" />
      </el-card>

      <el-card header="部门资产总览（IP 分配：管理人 / 资源使用部门 / 部门负责人）" style="margin-top: 12px">
        <el-form inline @submit.prevent>
          <el-form-item label="IP">
            <el-input v-model="overviewForm.ip" placeholder="模糊搜索 IP" clearable style="width: 180px" @keyup.enter="loadOverview" />
          </el-form-item>
          <el-form-item label="部门">
            <el-input v-model="overviewForm.dept" placeholder="部门前缀，如 平台与医技-医技中心" clearable style="width: 260px" @keyup.enter="loadOverview" />
          </el-form-item>
          <el-form-item>
            <el-button type="primary" :loading="overviewLoading" @click="onOverviewSearch">查询</el-button>
          </el-form-item>
        </el-form>
        <el-table :data="overview" v-loading="overviewLoading" style="width: 100%">
          <el-table-column prop="ip" label="内网IP" width="150" />
          <el-table-column prop="hostname" label="主机名" min-width="120">
            <template #default="{ row }">{{ String(row.hostname ?? '') || '-' }}</template>
          </el-table-column>
          <el-table-column prop="dept" label="资源使用部门" min-width="240" show-overflow-tooltip />
          <el-table-column prop="owner" label="管理人" width="130">
            <template #default="{ row }">{{ row.owner ?? '— 无主' }}</template>
          </el-table-column>
          <el-table-column prop="owner_dept" label="管理人隶属组织" min-width="220" show-overflow-tooltip>
            <template #default="{ row }">{{ String(row.owner_dept ?? '') || '-' }}</template>
          </el-table-column>
          <el-table-column prop="dept_leader" label="部门负责人" width="130">
            <template #default="{ row }">{{ String(row.dept_leader ?? '') || '-' }}</template>
          </el-table-column>
        </el-table>
        <el-pagination
          v-model:current-page="overviewPage"
          v-model:page-size="overviewPageSize"
          :total="overviewCount"
          :page-sizes="[20, 50, 100]"
          layout="total, sizes, prev, pager, next, jumper"
          style="margin-top: 12px; justify-content: flex-end"
          @current-change="loadOverview"
          @size-change="onOverviewSizeChange"
        />
        <div class="muted">部门负责人视角自动限定为其管辖部门（scope={{ overviewScope }}）；运营/管理员可见全量</div>
      </el-card>

      <el-card v-if="showOrphans" header="无主资产（GET /api/assets/orphans）" style="margin-top: 12px">
        <el-button size="small" :loading="orphanLoading" @click="loadOrphans">刷新</el-button>
        <el-table :data="orphans" v-loading="orphanLoading" style="width: 100%; margin-top: 8px">
          <el-table-column prop="ip" label="IP" width="160" />
          <el-table-column prop="hostname" label="主机名" min-width="180" />
          <el-table-column prop="status" label="状态" width="120" />
        </el-table>
        <div class="muted">共 {{ orphanCount }} 条（最多 200）</div>
      </el-card>

      <el-dialog v-model="createDlg.open" title="新建资产（离线/非CMDB资产手工录入）" width="480px">
        <el-form :model="createDlg" label-width="80px">
          <el-form-item label="IP" required>
            <el-input v-model="createDlg.ip" placeholder="如 10.9.0.20" clearable />
          </el-form-item>
          <el-form-item label="主机名">
            <el-input v-model="createDlg.hostname" clearable />
          </el-form-item>
          <el-form-item label="负责人">
            <el-input v-model="createDlg.owner" placeholder="用户名，不填则无主" clearable />
          </el-form-item>
        </el-form>
        <template #footer>
          <el-button @click="createDlg.open = false">取消</el-button>
          <el-button type="primary" :loading="creating" @click="onCreate">确认新建</el-button>
        </template>
      </el-dialog>
    </el-main>
  </el-container>
</template>

<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import MappingHistory from '../components/MappingHistory.vue'
import { fetchAssetMapping, fetchOrphans, fetchAssetOverview, postCmdbSync, createAsset, remapAsset, type AssetMapping, type AssetOverviewRow, type OrphanAsset } from '../api/cmdb'

const form = reactive({ ip: '' })
const mapping = ref<AssetMapping | null>(null)
const loading = ref(false)
const syncing = ref(false)
const showOrphans = ref(false)
const orphans = ref<OrphanAsset[]>([])
const orphanCount = ref(0)
const orphanLoading = ref(false)
const remapForm = reactive({ username: '' })
const remapping = ref(false)
const creating = ref(false)
const createDlg = reactive({ open: false, ip: '', hostname: '', owner: '' })

const overviewForm = reactive({ ip: '', dept: '' })
const overview = ref<AssetOverviewRow[]>([])
const overviewCount = ref(0)
const overviewScope = ref('all')
const overviewPage = ref(1)
const overviewPageSize = ref(20)
const overviewLoading = ref(false)

async function loadOverview() {
  overviewLoading.value = true
  try {
    const res = await fetchAssetOverview({
      q: overviewForm.ip.trim() || undefined,
      dept: overviewForm.dept.trim() || undefined,
      page: overviewPage.value,
      page_size: overviewPageSize.value,
    })
    overview.value = res.results
    overviewCount.value = res.count
    overviewScope.value = res.scope ?? 'all'
  } catch (e: unknown) {
    const err = e as { response?: { data?: { friendly?: string; detail?: string } } }
    ElMessage.error(err.response?.data?.friendly ?? err.response?.data?.detail ?? '加载资产总览失败')
  } finally {
    overviewLoading.value = false
  }
}

function onOverviewSizeChange() {
  overviewPage.value = 1
  void loadOverview()
}

function onOverviewSearch() {
  overviewPage.value = 1
  void loadOverview()
}

onMounted(() => {
  void loadOverview()
})

async function onSearch() {
  if (!form.ip.trim()) {
    ElMessage.warning('请输入 IP')
    return
  }
  loading.value = true
  try {
    mapping.value = await fetchAssetMapping(form.ip.trim())
  } catch (e: unknown) {
    const err = e as { response?: { status?: number; data?: { friendly?: string; detail?: string } } }
    if (err.response?.status === 404) ElMessage.error(`未知资产 ${form.ip.trim()}`)
    else ElMessage.error(err.response?.data?.friendly ?? err.response?.data?.detail ?? '查询映射失败')
  } finally {
    loading.value = false
  }
}

async function onSync() {
  syncing.value = true
  try {
    const s = await postCmdbSync()
    ElMessage.success(`CMDB 同步完成：新增 ${s.upserted} / 重映射 ${s.remapped} / 无主 ${s.orphaned}`)
  } catch (e: unknown) {
    const err = e as { response?: { data?: { friendly?: string; detail?: string } } }
    ElMessage.error(err.response?.data?.friendly ?? err.response?.data?.detail ?? 'CMDB 同步失败')
  } finally {
    syncing.value = false
  }
}

async function loadOrphans() {
  orphanLoading.value = true
  try {
    const res = await fetchOrphans()
    orphans.value = res.results
    orphanCount.value = res.count
  } catch (e: unknown) {
    const err = e as { response?: { data?: { friendly?: string; detail?: string } } }
    ElMessage.error(err.response?.data?.friendly ?? err.response?.data?.detail ?? '加载无主资产失败')
  } finally {
    orphanLoading.value = false
  }
}

function apiErr(e: unknown, fallback: string): string {
  const err = e as { response?: { data?: { friendly?: string; detail?: string } } }
  return err.response?.data?.friendly ?? err.response?.data?.detail ?? fallback
}

async function onRemap() {
  if (!mapping.value) return
  remapping.value = true
  try {
    const res = await remapAsset(mapping.value.ip, remapForm.username.trim() || undefined)
    ElMessage.success(`已变更负责人为 ${res.owner ?? '无主'}，重派 ${res.remapped} 张工单`)
    remapForm.username = ''
    mapping.value = await fetchAssetMapping(mapping.value.ip)
  } catch (e: unknown) {
    ElMessage.error(apiErr(e, '变更负责人失败'))
  } finally {
    remapping.value = false
  }
}

async function onCreate() {
  if (!createDlg.ip.trim()) {
    ElMessage.warning('请填写 IP')
    return
  }
  creating.value = true
  try {
    const res = await createAsset({
      ip: createDlg.ip.trim(),
      hostname: createDlg.hostname.trim() || undefined,
      owner: createDlg.owner.trim() || undefined,
    })
    ElMessage.success(`已新建资产 ${res.ip}${res.owner ? `（负责人 ${res.owner}）` : ''}`)
    createDlg.open = false
    createDlg.ip = ''
    createDlg.hostname = ''
    createDlg.owner = ''
  } catch (e: unknown) {
    ElMessage.error(apiErr(e, '新建资产失败'))
  } finally {
    creating.value = false
  }
}
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
  margin-top: 8px;
}
</style>
