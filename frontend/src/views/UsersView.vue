<template>
  <el-container>
    <el-header class="bar">
      <span>用户管理（运营）</span>
      <el-button link @click="$router.push('/ops')">返回工单池</el-button>
    </el-header>
    <el-main>
      <el-card>
        <el-form inline :model="filters">
          <el-form-item label="搜索">
            <el-input v-model="filters.q" placeholder="用户名" clearable style="width: 160px" @keyup.enter="load(1)" />
          </el-form-item>
          <el-form-item label="角色">
            <el-select v-model="filters.role" placeholder="全部" clearable style="width: 130px">
              <el-option v-for="r in roles" :key="r" :label="r" :value="r" />
            </el-select>
          </el-form-item>
          <el-form-item>
            <el-button type="primary" @click="load(1)">查询</el-button>
            <el-button @click="openCreate">新建用户</el-button>
          </el-form-item>
        </el-form>
        <el-table :data="rows" v-loading="loading" style="width: 100%">
          <el-table-column prop="username" label="用户名" width="150" />
          <el-table-column prop="dept" label="部门" min-width="280" show-overflow-tooltip />
          <el-table-column prop="email" label="邮箱" width="200" show-overflow-tooltip />
          <el-table-column prop="role" label="角色" width="110" />
          <el-table-column prop="wecom_userid" label="企微账号" width="140" />
          <el-table-column label="状态" width="90">
            <template #default="{ row }">
              <el-tag :type="row.is_active ? 'success' : 'danger'">{{ row.is_active ? '在用' : '停用' }}</el-tag>
            </template>
          </el-table-column>
          <el-table-column label="操作" width="230" fixed="right">
            <template #default="{ row }">
              <el-button size="small" @click="openEdit(row)">编辑</el-button>
              <el-button size="small" @click="onToggle(row)">{{ row.is_active ? '停用' : '启用' }}</el-button>
              <el-button size="small" type="warning" @click="onReset(row)">重置密码</el-button>
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

      <el-dialog v-model="createOpen" title="新建用户">
        <el-form :model="createForm" label-width="90px">
          <el-form-item label="用户名"><el-input v-model="createForm.username" placeholder="建议=企微账号，打通扫码登录" /></el-form-item>
          <el-form-item label="部门"><el-input v-model="createForm.dept" /></el-form-item>
          <el-form-item label="邮箱"><el-input v-model="createForm.email" placeholder="邮件通知用" /></el-form-item>
          <el-form-item label="角色">
            <el-select v-model="createForm.role" style="width: 100%">
              <el-option v-for="r in roles" :key="r" :label="r" :value="r" />
            </el-select>
          </el-form-item>
          <el-form-item label="企微账号"><el-input v-model="createForm.wecom_userid" placeholder="空=本地账号；填了可扫码登录" /></el-form-item>
          <el-form-item label="初始密码"><el-input v-model="createForm.password" placeholder="空=自动生成（仅显示一次）" /></el-form-item>
        </el-form>
        <template #footer>
          <el-button @click="createOpen = false">取消</el-button>
          <el-button type="primary" :loading="acting" @click="onCreate">创建</el-button>
        </template>
      </el-dialog>

      <el-dialog v-model="editOpen" title="编辑用户">
        <el-form :model="editForm" label-width="90px">
          <el-form-item label="部门"><el-input v-model="editForm.dept" /></el-form-item>
          <el-form-item label="邮箱"><el-input v-model="editForm.email" /></el-form-item>
          <el-form-item label="角色">
            <el-select v-model="editForm.role" style="width: 100%">
              <el-option v-for="r in roles" :key="r" :label="r" :value="r" />
            </el-select>
          </el-form-item>
          <el-form-item label="企微账号"><el-input v-model="editForm.wecom_userid" /></el-form-item>
        </el-form>
        <template #footer>
          <el-button @click="editOpen = false">取消</el-button>
          <el-button type="danger" plain :loading="acting" @click="onDeleteUser">删除用户</el-button>
          <el-button type="primary" :loading="acting" @click="onEdit">保存</el-button>
        </template>
      </el-dialog>

      <el-dialog v-model="pwdOpen" title="重置密码" width="420px">
        <p>
          将重置 <b>{{ pwdUser }}</b> 的密码<span v-if="!pwdCustom">（自动生成，仅显示一次）</span>。
        </p>
        <el-input v-model="pwdCustom" placeholder="空=自动生成；或填指定密码" clearable style="margin-top: 8px" />
        <p v-if="pwdResult" class="mono" style="margin-top: 8px">新密码：{{ pwdResult }}</p>
        <template #footer>
          <el-button @click="pwdOpen = false">关闭</el-button>
          <el-button type="primary" :loading="acting" @click="onResetConfirm">确认重置</el-button>
        </template>
      </el-dialog>
    </el-main>
  </el-container>
</template>

<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import {
  fetchAdminUsers,
  createAdminUser,
  patchAdminUser,
  resetAdminPassword,
  deleteAdminUser,
  type AdminUser,
} from '../api/users'

const roles = ['owner', 'leader', 'operator', 'auditor']
const filters = reactive({ q: '', role: '' })
const rows = ref<AdminUser[]>([])
const total = ref(0)
const page = ref(1)
const pageSize = ref(20)
const loading = ref(false)
const acting = ref(false)

const createOpen = ref(false)
const createForm = reactive({ username: '', dept: '', email: '', role: 'owner', wecom_userid: '', password: '' })
const editOpen = ref(false)
const editUser = ref('')
const editForm = reactive({ dept: '', email: '', role: 'owner', wecom_userid: '' })
const pwdOpen = ref(false)
const pwdUser = ref('')
const pwdCustom = ref('')
const pwdResult = ref('')

function errText(e: unknown, fallback: string): string {
  const err = e as { response?: { data?: { friendly?: string; detail?: string } } }
  return err.response?.data?.friendly ?? err.response?.data?.detail ?? fallback
}

async function load(p = 1) {
  loading.value = true
  page.value = p
  try {
    const res = await fetchAdminUsers({ page: p, page_size: pageSize.value, ...(filters.q ? { q: filters.q } : {}), ...(filters.role ? { role: filters.role } : {}) })
    rows.value = res.results
    total.value = res.count
  } catch (e: unknown) {
    ElMessage.error(errText(e, '加载用户失败'))
  } finally {
    loading.value = false
  }
}

function openCreate() {
  Object.assign(createForm, { username: '', dept: '', email: '', role: 'owner', wecom_userid: '', password: '' })
  createOpen.value = true
}

async function onCreate() {
  if (!createForm.username.trim()) {
    ElMessage.warning('请填写用户名')
    return
  }
  acting.value = true
  try {
    const res = await createAdminUser({ ...createForm, username: createForm.username.trim() })
    createOpen.value = false
    if (res.temp_password) {
      await ElMessageBox.alert(`账号 ${res.username} 已创建，临时密码（仅显示一次）：${res.temp_password}`, '创建成功')
    } else {
      ElMessage.success('创建成功')
    }
    await load(page.value)
  } catch (e: unknown) {
    ElMessage.error(errText(e, '创建失败'))
  } finally {
    acting.value = false
  }
}

function openEdit(row: AdminUser) {
  editUser.value = String(row.username)
  Object.assign(editForm, { dept: row.dept ?? '', email: row.email ?? '', role: row.role, wecom_userid: row.wecom_userid ?? '' })
  editOpen.value = true
}

async function onEdit() {
  acting.value = true
  try {
    await patchAdminUser(editUser.value, { ...editForm })
    ElMessage.success('已保存')
    editOpen.value = false
    await load(page.value)
  } catch (e: unknown) {
    ElMessage.error(errText(e, '保存失败'))
  } finally {
    acting.value = false
  }
}

async function onDeleteUser() {
  const username = editUser.value
  if (!username) return
  try {
    await ElMessageBox.confirm(
      `确定永久删除用户 ${username}？其名下未关闭工单将自动退回工单池，资产映射与部门负责人绑定一并清除（审计留痕），不可恢复。`,
      '删除用户',
      { type: 'warning', confirmButtonText: '删除', cancelButtonText: '取消' },
    )
  } catch {
    return
  }
  acting.value = true
  try {
    const res = await deleteAdminUser(username)
    ElMessage.success(
      `用户 ${username} 已删除${res.unassigned_open_tickets ? `，${res.unassigned_open_tickets} 张在办工单已退回工单池` : ''}`,
    )
    editOpen.value = false
    await load(page.value)
  } catch (e: unknown) {
    ElMessage.error(errText(e, '删除失败'))
  } finally {
    acting.value = false
  }
}

async function onToggle(row: AdminUser) {
  if (row.is_active) {
    try {
      await ElMessageBox.confirm(
        `停用后 ${row.username} 无法登录，其名下未关闭工单将自动退回工单池（负责人清空）。确认停用？`,
        '停用确认',
        { type: 'warning', confirmButtonText: '停用', cancelButtonText: '取消' },
      )
    } catch {
      return
    }
  }
  acting.value = true
  try {
    const res = (await patchAdminUser(String(row.username), { is_active: !row.is_active })) as AdminUser & { unassigned_open_tickets?: number }
    if (row.is_active && typeof res.unassigned_open_tickets === 'number') {
      ElMessage.success(`已停用，${res.unassigned_open_tickets} 张在办工单已退回工单池`)
    } else {
      ElMessage.success(row.is_active ? '已停用' : '已启用')
    }
    await load(page.value)
  } catch (e: unknown) {
    ElMessage.error(errText(e, '操作失败'))
  } finally {
    acting.value = false
  }
}

function onReset(row: AdminUser) {
  pwdUser.value = String(row.username)
  pwdCustom.value = ''
  pwdResult.value = ''
  pwdOpen.value = true
}

async function onResetConfirm() {
  acting.value = true
  try {
    const res = await resetAdminPassword(pwdUser.value, pwdCustom.value.trim() || undefined)
    pwdResult.value = res.temp_password ?? '(已按指定密码重置)'
    ElMessage.success('密码已重置')
  } catch (e: unknown) {
    ElMessage.error(errText(e, '重置失败'))
  } finally {
    acting.value = false
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
.mono {
  font-family: monospace;
  font-size: 13px;
  word-break: break-all;
}
</style>
