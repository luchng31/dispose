<template>
  <el-container>
    <el-header class="bar">
      <span>二次验证（TOTP）</span>
      <span class="user">{{ auth.user?.username }} ({{ auth.user?.role }})</span>
      <el-button link @click="$router.push('/my')">我的工单</el-button>
      <el-button link @click="onLogout">退出</el-button>
    </el-header>
    <el-main>
      <el-card style="max-width: 640px">
        <template v-if="enrolled === null">
          <el-skeleton :rows="3" animated />
        </template>

        <template v-else-if="enrolled">
          <el-result icon="success" title="已绑定二次验证" sub-title="登录时需输入验证器 App 中的 6 位动态码">
            <template #extra>
              <el-button type="danger" plain :loading="acting" @click="dlg.open = true">解绑（手机丢失时用）</el-button>
            </template>
          </el-result>
        </template>

        <template v-else-if="!setup">
          <el-alert type="info" :closable="false" show-icon title="绑定后登录需多输入 6 位动态码，防密码泄露" />
          <el-button type="primary" :loading="acting" style="margin-top: 12px" @click="onSetup">开始绑定</el-button>
        </template>

        <template v-else>
          <el-steps :active="1" simple style="margin-bottom: 12px">
            <el-step title="验证器 App 手工录入" />
            <el-step title="输入动态码确认" />
          </el-steps>
          <el-descriptions :column="1" border>
            <el-descriptions-item label="密钥">
              <span class="secret">{{ formatTotpSecret(setup.secret) }}</span>
              <el-button link type="primary" @click="onCopySecret">复制</el-button>
            </el-descriptions-item>
            <el-descriptions-item label="otpauth 链接">
              <span class="cell-ellipsis" :title="setup.otpauth_url">{{ setup.otpauth_url }}</span>
              <el-button link type="primary" @click="onCopyUrl">复制</el-button>
            </el-descriptions-item>
          </el-descriptions>
          <p class="muted">在 Microsoft Authenticator / Google Authenticator / 1Password 中选"手动输入设置密钥"，粘贴上方密钥，账户名填你自己的用户名。</p>
          <el-form inline @submit.prevent>
            <el-form-item label="动态码">
              <el-input v-model="code" placeholder="6 位数字" maxlength="8" style="width: 160px" @keyup.enter="onConfirm" />
            </el-form-item>
            <el-form-item>
              <el-button type="primary" :loading="acting" @click="onConfirm">确认绑定</el-button>
            </el-form-item>
          </el-form>
        </template>
      </el-card>

      <el-dialog v-model="dlg.open" title="解绑二次验证" width="420px">
        <el-form label-width="70px" @submit.prevent>
          <el-form-item label="登录密码">
            <el-input v-model="dlg.password" type="password" show-password autocomplete="current-password" />
          </el-form-item>
        </el-form>
        <template #footer>
          <el-button @click="dlg.open = false">取消</el-button>
          <el-button type="danger" :loading="acting" @click="onDisable">确认解绑</el-button>
        </template>
      </el-dialog>
    </el-main>
  </el-container>
</template>

<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { confirmTotp, disableTotp, formatTotpSecret, setupTotp, type TotpSetup } from '../api/mfa'
import { useAuthStore } from '../stores/auth'

const router = useRouter()
const auth = useAuthStore()
auth.hydrate()

const enrolled = ref<boolean | null>(null)
const setup = ref<TotpSetup | null>(null)
const code = ref('')
const acting = ref(false)
const dlg = reactive({ open: false, password: '' })

function errText(e: unknown, fallback: string): string {
  const err = e as { response?: { data?: { friendly?: string; detail?: string } } }
  return err.response?.data?.friendly ?? err.response?.data?.detail ?? fallback
}

async function refreshEnrolled() {
  try {
    const me = await auth.refreshMe()
    enrolled.value = me?.totp_enrolled ?? auth.user?.totp_enrolled ?? false
  } catch {
    enrolled.value = auth.user?.totp_enrolled ?? false
  }
}

async function onSetup() {
  acting.value = true
  try {
    setup.value = await setupTotp()
    code.value = ''
  } catch (e: unknown) {
    ElMessage.error(errText(e, '发起绑定失败'))
  } finally {
    acting.value = false
  }
}

async function onConfirm() {
  if (!setup.value || !code.value.trim()) {
    ElMessage.warning('请先输入验证器 App 中的 6 位动态码')
    return
  }
  acting.value = true
  try {
    await confirmTotp(setup.value.secret, code.value.trim())
    setup.value = null
    await refreshEnrolled()
    ElMessage.success('二次验证已绑定')
  } catch (e: unknown) {
    ElMessage.error(errText(e, '动态码不正确'))
  } finally {
    acting.value = false
  }
}

async function onDisable() {
  if (!dlg.password) {
    ElMessage.warning('请输入登录密码')
    return
  }
  acting.value = true
  try {
    await disableTotp(dlg.password)
    dlg.open = false
    dlg.password = ''
    await refreshEnrolled()
    ElMessage.success('已解绑二次验证')
  } catch (e: unknown) {
    ElMessage.error(errText(e, '解绑失败'))
  } finally {
    acting.value = false
  }
}

async function copyText(text: string, okMsg: string) {
  try {
    await navigator.clipboard.writeText(text)
    ElMessage.success(okMsg)
  } catch {
    ElMessage.warning('复制失败，请手动选择复制')
  }
}

function onCopySecret() {
  if (setup.value) void copyText(setup.value.secret, '密钥已复制')
}

function onCopyUrl() {
  if (setup.value) void copyText(setup.value.otpauth_url, '链接已复制')
}

function onLogout() {
  auth.logout()
  void router.push('/login')
}

onMounted(() => {
  void refreshEnrolled()
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
.secret {
  font-family: ui-monospace, monospace;
  font-weight: 600;
  letter-spacing: 1px;
}
.muted {
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
