<template>
  <el-card header="Dry-Run 预览（后端计数原文展示，不做客户端重算）">
    <el-descriptions :column="2" border>
      <el-descriptions-item label="新增 new">{{ preview.new }}</el-descriptions-item>
      <el-descriptions-item label="仍开放 still_open">{{ preview.still_open }}</el-descriptions-item>
      <el-descriptions-item label="已修复未验证 fixed_unverified">{{ preview.fixed_unverified }}</el-descriptions-item>
      <el-descriptions-item label="重现 reopened">{{ preview.reopened }}</el-descriptions-item>
      <el-descriptions-item label="文件哈希">{{ preview.file_hash }}</el-descriptions-item>
      <el-descriptions-item label="跳过 skipped">{{ preview.skipped ? '是' : '否' }}</el-descriptions-item>
    </el-descriptions>
    <div style="margin-top: 12px">
      <span class="muted">错误行 errors[{{ preview.errors.length }}]</span>
      <el-table :data="preview.errors" style="width: 100%" max-height="260">
        <el-table-column label="行" width="90">
          <template #default="{ row }">{{ String((row as Record<string, unknown>).row ?? '-') }}</template>
        </el-table-column>
        <el-table-column label="字段" width="120">
          <template #default="{ row }">{{ String((row as Record<string, unknown>).field ?? '-') }}</template>
        </el-table-column>
        <el-table-column label="信息" min-width="220">
          <template #default="{ row }">{{ String((row as Record<string, unknown>).message ?? JSON.stringify(row)) }}</template>
        </el-table-column>
      </el-table>
      <el-empty v-if="!preview.errors.length" description="无错误行" />
    </div>
  </el-card>
</template>

<script setup lang="ts">
import type { DryRunCounts } from '../utils/ops'

defineProps<{ preview: DryRunCounts }>()
</script>

<style scoped>
.muted {
  color: #999;
  font-size: 12px;
}
</style>
