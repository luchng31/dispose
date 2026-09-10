<template>
  <el-container>
    <el-header class="bar">
      <span>资产与负责人导入</span>
      <el-button link @click="$router.push('/ops/imports')">漏洞导入</el-button>
      <el-button link @click="$router.push('/ops')">返回工单池</el-button>
    </el-header>
    <el-main>
      <el-card header="资产汇总表导入（服务器资源汇总表 .xlsx / .csv）">
        <p class="muted">列：内网IP*, 管理人*, 管人-隶属组织, 资源使用部门, 部门负责人（「姓名(工号)」自动拆分建号）。</p>
        <p class="muted">
          <b>以最新导入为准全量同步</b>：本表未出现的现任 IP 自动置无主（资产保留、在办工单转无主池），部门负责人映射按新表重建。
          Dry-Run 会预览将被置无主的 IP 数（orphaned_preview），确认无误再导入。
        </p>
        <el-upload
          drag
          :auto-upload="false"
          :limit="1"
          accept=".csv,.xlsx"
          :on-change="onAssetChange"
          :on-remove="onAssetRemove"
          style="margin-top: 8px"
        >
          <div class="el-upload__text">拖拽 xlsx/CSV 到此处或 <em>点击选择</em></div>
        </el-upload>
        <div class="actions">
          <el-button size="small" @click="onTemplate">下载模板</el-button>
        </div>
        <div class="actions">
          <el-button type="primary" :disabled="!assetFile" :loading="assetPreviewing" @click="onAssetDryRun">
            Dry-Run 预览
          </el-button>
          <el-button type="success" :disabled="assetPreview == null" :loading="assetConfirming" @click="onAssetConfirm">
            确认导入（全量同步）
          </el-button>
        </div>
        <el-descriptions v-if="assetPreview" :column="3" border style="margin-top: 8px">
          <el-descriptions-item label="有效行">{{ assetPreview.valid }}</el-descriptions-item>
          <el-descriptions-item label="无效行">{{ assetPreview.invalid }}</el-descriptions-item>
          <el-descriptions-item v-if="assetPreview.orphaned_preview != null" label="将被置无主 IP">
            <span class="warn">{{ assetPreview.orphaned_preview }}</span>
          </el-descriptions-item>
        </el-descriptions>
        <el-card v-if="assetResult" header="导入结果" style="margin-top: 8px">
          <el-descriptions :column="3" border>
            <el-descriptions-item label="新建资产">{{ assetResult.created_assets }}</el-descriptions-item>
            <el-descriptions-item label="更新资产">{{ assetResult.updated_assets }}</el-descriptions-item>
            <el-descriptions-item label="改派映射">{{ assetResult.remapped }}</el-descriptions-item>
            <el-descriptions-item label="重派工单">{{ assetResult.dispatched }}</el-descriptions-item>
            <el-descriptions-item label="新建部门负责人">{{ assetResult.created_leaders ?? 0 }}</el-descriptions-item>
            <el-descriptions-item label="置无主 IP">{{ assetResult.orphaned ?? 0 }}</el-descriptions-item>
          </el-descriptions>
          <el-alert
            v-if="assetResult.leader_maps_rebuilt"
            type="warning"
            :closable="false"
            title="部门负责人映射已按本次导入的表重建（旧绑定已清除）"
            style="margin-top: 8px"
          />
          <el-table v-if="assetResult.created_users.length" :data="assetResult.created_users" style="width: 100%; margin-top: 8px">
            <el-table-column prop="username" label="新建账号" width="180" />
            <el-table-column prop="role" label="角色" width="110">
              <template #default="{ row }">{{ row.role === 'leader' ? '部门负责人' : '资产负责人' }}</template>
            </el-table-column>
            <el-table-column prop="temp_password" label="临时密码（仅显示一次）" min-width="200">
              <template #default="{ row }"><span class="mono">{{ String(row.temp_password ?? '') }}</span></template>
            </el-table-column>
          </el-table>
          <el-table v-if="assetResult.errors.length" :data="assetResult.errors" style="width: 100%; margin-top: 8px">
            <el-table-column prop="row" label="行" width="80" />
            <el-table-column prop="message" label="错误" min-width="200" />
          </el-table>
        </el-card>
      </el-card>

      <el-card header="负责人邮箱表导入（更新已有账号的邮箱，不建号）" style="margin-top: 12px">
        <p class="muted">列：负责人（姓名(工号)）或 工号* + 邮箱*（.xlsx/.csv）。匹配不到账号的行会列入 missing，请先在资产汇总表或用户管理中建号。</p>
        <el-upload
          drag
          :auto-upload="false"
          :limit="1"
          accept=".csv,.xlsx"
          :on-change="onEmailChange"
          :on-remove="onEmailRemove"
          style="margin-top: 8px"
        >
          <div class="el-upload__text">拖拽 xlsx/CSV 到此处或 <em>点击选择</em></div>
        </el-upload>
        <div class="actions">
          <el-button size="small" @click="onEmailTemplate">下载模板</el-button>
        </div>
        <div class="actions">
          <el-button type="primary" :disabled="!emailFile" :loading="emailPreviewing" @click="onEmailDryRun">
            Dry-Run 预览
          </el-button>
          <el-button type="success" :disabled="emailPreview == null" :loading="emailConfirming" @click="onEmailConfirm">
            确认导入
          </el-button>
        </div>
        <el-descriptions v-if="emailPreview" :column="3" border style="margin-top: 8px">
          <el-descriptions-item label="总行数">{{ emailPreview.total_rows }}</el-descriptions-item>
          <el-descriptions-item label="将更新">{{ emailPreview.updated_preview ?? 0 }}</el-descriptions-item>
          <el-descriptions-item label="匹配不到">{{ emailPreview.missing.length }}</el-descriptions-item>
        </el-descriptions>
        <el-card v-if="emailResult" header="导入结果" style="margin-top: 8px">
          <el-descriptions :column="3" border>
            <el-descriptions-item label="已更新">{{ emailResult.updated }}</el-descriptions-item>
            <el-descriptions-item label="未变化">{{ emailResult.unchanged }}</el-descriptions-item>
            <el-descriptions-item label="匹配不到">{{ emailResult.missing.length }}</el-descriptions-item>
          </el-descriptions>
          <el-table v-if="emailResult.missing.length" :data="emailResult.missing" style="width: 100%; margin-top: 8px">
            <el-table-column prop="row" label="行" width="80" />
            <el-table-column prop="name" label="负责人/工号" min-width="160" />
          </el-table>
          <el-table v-if="emailResult.errors.length" :data="emailResult.errors" style="width: 100%; margin-top: 8px">
            <el-table-column prop="row" label="行" width="80" />
            <el-table-column prop="message" label="错误" min-width="200" />
          </el-table>
        </el-card>
      </el-card>
    </el-main>
  </el-container>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import { ElMessage } from 'element-plus'
import type { UploadFile } from 'element-plus'
import {
  postAssetImport,
  postOwnerEmailImport,
  downloadAssetTemplate,
  downloadOwnerEmailTemplate,
  type AssetImportSummary,
  type OwnerEmailImportSummary,
} from '../api/imports'

function apiErr(e: unknown, fallback: string): string {
  const err = e as { response?: { data?: { errors?: Array<{ message?: string }> } & { friendly?: string; detail?: string } } }
  return err.response?.data?.errors?.[0]?.message ?? err.response?.data?.friendly ?? err.response?.data?.detail ?? fallback
}

const assetFile = ref<File | null>(null)
const assetPreview = ref<{ valid?: number; invalid?: number; orphaned_preview?: number } | null>(null)
const assetPreviewing = ref(false)
const assetConfirming = ref(false)
const assetResult = ref<AssetImportSummary | null>(null)

function onAssetChange(up: UploadFile) {
  assetFile.value = (up.raw as File | undefined) ?? null
  assetPreview.value = null
  assetResult.value = null
}

function onAssetRemove() {
  assetFile.value = null
  assetPreview.value = null
  assetResult.value = null
}

async function onTemplate() {
  try {
    await downloadAssetTemplate()
  } catch {
    ElMessage.error('模板下载失败')
  }
}

async function onAssetDryRun() {
  if (!assetFile.value) {
    ElMessage.warning('请先选择 xlsx/CSV 文件')
    return
  }
  assetPreviewing.value = true
  try {
    const res = await postAssetImport(assetFile.value, true)
    assetPreview.value = res
    ElMessage.success(
      `Dry-Run：有效 ${res.valid ?? 0} 行，无效 ${res.invalid ?? 0} 行${res.orphaned_preview != null ? `，将置无主 ${res.orphaned_preview} 个 IP` : ''}（零写库）`,
    )
  } catch (e: unknown) {
    ElMessage.error(apiErr(e, 'Dry-Run 失败'))
  } finally {
    assetPreviewing.value = false
  }
}

async function onAssetConfirm() {
  if (!assetFile.value || assetPreview.value == null) {
    ElMessage.warning('请先做 Dry-Run 预览')
    return
  }
  assetConfirming.value = true
  try {
    const res = await postAssetImport(assetFile.value, false)
    assetResult.value = res
    ElMessage.success(
      `已导入：资产+${res.created_assets} ~${res.updated_assets}，置无主 ${res.orphaned ?? 0}，重派 ${res.dispatched}`,
    )
    assetPreview.value = null
  } catch (e: unknown) {
    ElMessage.error(apiErr(e, '导入失败'))
  } finally {
    assetConfirming.value = false
  }
}

const emailFile = ref<File | null>(null)
const emailPreview = ref<OwnerEmailImportSummary | null>(null)
const emailPreviewing = ref(false)
const emailConfirming = ref(false)
const emailResult = ref<OwnerEmailImportSummary | null>(null)

function onEmailChange(up: UploadFile) {
  emailFile.value = (up.raw as File | undefined) ?? null
  emailPreview.value = null
  emailResult.value = null
}

function onEmailRemove() {
  emailFile.value = null
  emailPreview.value = null
  emailResult.value = null
}

async function onEmailTemplate() {
  try {
    await downloadOwnerEmailTemplate()
  } catch {
    ElMessage.error('模板下载失败')
  }
}

async function onEmailDryRun() {
  if (!emailFile.value) {
    ElMessage.warning('请先选择 xlsx/CSV 文件')
    return
  }
  emailPreviewing.value = true
  try {
    const res = await postOwnerEmailImport(emailFile.value, true)
    emailPreview.value = res
    ElMessage.success(`Dry-Run：将更新 ${res.updated_preview ?? 0} 个账号（零写库）`)
  } catch (e: unknown) {
    ElMessage.error(apiErr(e, 'Dry-Run 失败'))
  } finally {
    emailPreviewing.value = false
  }
}

async function onEmailConfirm() {
  if (!emailFile.value || emailPreview.value == null) {
    ElMessage.warning('请先做 Dry-Run 预览')
    return
  }
  emailConfirming.value = true
  try {
    const res = await postOwnerEmailImport(emailFile.value, false)
    emailResult.value = res
    ElMessage.success(
      `已导入：更新 ${res.updated} 个邮箱${res.missing.length ? `，${res.missing.length} 行匹配不到账号` : ''}`,
    )
    emailPreview.value = null
  } catch (e: unknown) {
    ElMessage.error(apiErr(e, '导入失败'))
  } finally {
    emailConfirming.value = false
  }
}
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
.muted {
  color: #999;
  font-size: 12px;
  margin-top: 6px;
}
.warn {
  color: #e6a23c;
  font-weight: bold;
}
</style>
