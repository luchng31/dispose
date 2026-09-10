<template>
  <el-container>
    <el-header class="bar">
      <span>漏洞导入（RSAS ZIP）</span>
      <el-button link @click="$router.push('/ops/imports/assets')">资产与负责人导入</el-button>
      <el-button link @click="$router.push('/ops')">返回工单池</el-button>
    </el-header>
    <el-main>
      <el-card header="手工上传 ZIP">
        <el-upload
          drag
          :auto-upload="false"
          :limit="1"
          accept=".zip"
          :on-change="onFileChange"
          :on-remove="onFileRemove"
        >
          <div class="el-upload__text">拖拽 ZIP 到此处或 <em>点击选择</em></div>
        </el-upload>
        <div class="actions">
          <el-button type="primary" :disabled="!file" :loading="previewing" @click="onDryRun">
            Dry-Run 预览
          </el-button>
          <el-button type="success" :disabled="!preview" :loading="confirming" @click="onConfirm">
            确认入库
          </el-button>
        </div>
      </el-card>

      <div style="margin-top: 12px">
        <DryRunPreview v-if="preview" :preview="preview" />
      </div>

      <el-card header="导入批次（file_hash + stats）" style="margin-top: 12px">
        <el-button size="small" @click="loadBatches">刷新</el-button>
        <el-table :data="batches" v-loading="batchLoading" style="width: 100%; margin-top: 8px">
          <el-table-column prop="id" label="ID" width="80" />
          <el-table-column prop="file_name" label="文件名" min-width="200" />
          <el-table-column prop="file_hash" label="file_hash" min-width="240">
            <template #default="{ row }"><span class="mono">{{ String(row.file_hash ?? '') }}</span></template>
          </el-table-column>
          <el-table-column prop="source" label="来源" width="100" />
          <el-table-column label="stats" min-width="220">
            <template #default="{ row }">{{ JSON.stringify(row.stats ?? {}) }}</template>
          </el-table-column>
          <el-table-column prop="created_at" label="创建时间" width="180" />
        </el-table>
      </el-card>
    </el-main>
  </el-container>
</template>

<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import type { UploadFile } from 'element-plus'
import DryRunPreview from '../components/DryRunPreview.vue'
import { fetchBatches, postRsasImport, type ScanBatch } from '../api/imports'
import { parseDryRun, type DryRunCounts } from '../utils/ops'

const file = ref<File | null>(null)
const preview = ref<DryRunCounts | null>(null)
const previewing = ref(false)
const confirming = ref(false)
const batches = ref<ScanBatch[]>([])
const batchLoading = ref(false)

function onFileChange(up: UploadFile) {
  file.value = (up.raw as File | undefined) ?? null
  preview.value = null
}

function onFileRemove() {
  file.value = null
  preview.value = null
}

async function onDryRun() {
  if (!file.value) {
    ElMessage.warning('请先选择 ZIP 文件')
    return
  }
  previewing.value = true
  try {
    const raw = await postRsasImport(file.value, true)
    preview.value = parseDryRun(raw)
    if (preview.value.skipped) ElMessage.warning('该文件已导入过（按 file_hash 跳过）')
    else ElMessage.success('Dry-Run 预览已生成（零写库）')
  } catch (e: unknown) {
    const err = e as { response?: { data?: { friendly?: string; detail?: string } } }
    ElMessage.error(err.response?.data?.friendly ?? err.response?.data?.detail ?? 'Dry-Run 失败')
  } finally {
    previewing.value = false
  }
}

async function onConfirm() {
  if (!file.value || !preview.value) {
    ElMessage.warning('请先做 Dry-Run 预览')
    return
  }
  confirming.value = true
  try {
    await postRsasImport(file.value, false)
    ElMessage.success('已确认入库')
    preview.value = null
    await loadBatches()
  } catch (e: unknown) {
    const err = e as { response?: { data?: { friendly?: string; detail?: string } } }
    ElMessage.error(err.response?.data?.friendly ?? err.response?.data?.detail ?? '入库失败')
  } finally {
    confirming.value = false
  }
}

async function loadBatches() {
  batchLoading.value = true
  try {
    batches.value = await fetchBatches()
  } catch (e: unknown) {
    const err = e as { response?: { data?: { friendly?: string; detail?: string } } }
    ElMessage.error(err.response?.data?.friendly ?? err.response?.data?.detail ?? '加载批次失败')
  } finally {
    batchLoading.value = false
  }
}

onMounted(() => {
  void loadBatches()
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
.mono {
  font-family: monospace;
  font-size: 12px;
  word-break: break-all;
}
</style>
