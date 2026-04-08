// 前端运行入口：在 Worker 返回的页面中直接执行
export function initMailDashboardApp() {
    // 基础 DOM 工具：减少重复的 getElementById 调用
    const $ = (id) => document.getElementById(id);
  
    // 页面节点缓存：列表、详情、状态与账户弹窗
    const listEl = $('list');
    const detailEl = $('detail');
    const countEl = $('count');
    const statusEl = $('status');
    const tokenModal = $('tokenModal');
    const accountListEl = $('accountList');
    const tokenModalInput = $('tokenModalInput');
    const accountFormTitle = $('accountFormTitle');
    const accountNameInput = $('accountNameInput');
    const accountEmailInput = $('accountEmailInput');
    const accountSelect = $('accountSelect');
    const manageAccountsBtn = $('manageAccountsBtn');
    const accountResetBtn = $('accountResetBtn');
    const tokenSaveBtn = $('tokenSaveBtn');
    const tokenCancelBtn = $('tokenCancelBtn');
  
    // 本地存储键
    const STORAGE_ACCOUNTS = 'cf_mail_accounts';
    const STORAGE_ACTIVE_ACCOUNT = 'cf_mail_active_account';
  
      // 账户存储：读取、清洗、持久化
      function loadAccounts() {
        try {
          const raw = localStorage.getItem(STORAGE_ACCOUNTS);
          const parsed = raw ? JSON.parse(raw) : [];
          if (Array.isArray(parsed)) return parsed;
        } catch (_) {
          // 忽略脏数据，回退为空列表
        }
        return [];
      }
  
      function sanitizeAccount(account) {
        return {
          id: String(account.id || '').trim(),
          name: String(account.name || '').trim(),
          email: String(account.email || '').trim(),
          token: String(account.token || '').trim(),
        };
      }
  
      const legacyToken = localStorage.getItem('cf_mail_token') || '';
      let accounts = loadAccounts().map(sanitizeAccount).filter((a) => a.id && a.name);
      if (!accounts.length && legacyToken) {
        accounts = [{
          id: 'acc-' + Date.now(),
          name: '默认账户',
          email: '',
          token: legacyToken,
        }];
      }
  
      let activeAccountId = localStorage.getItem(STORAGE_ACTIVE_ACCOUNT) || accounts[0]?.id || null;
      if (accounts.length && !accounts.some((a) => a.id === activeAccountId)) {
        activeAccountId = accounts[0].id;
      }
  
      let state = {
        messages: [],
        currentId: null,
        accounts,
        activeAccountId,
        editingAccountId: null,
      };
  
      function resetAccountForm() {
        state.editingAccountId = null;
        accountNameInput.value = '';
        accountEmailInput.value = '';
        tokenModalInput.value = '';
        accountFormTitle.textContent = '新增账户';
        tokenSaveBtn.textContent = '新增账户';
        accountResetBtn.style.display = 'none';
      }
  
      function startEditAccount(accountId) {
        const account = state.accounts.find((item) => item.id === accountId);
        if (!account) return;
  
        state.editingAccountId = account.id;
        accountNameInput.value = account.name || '';
        accountEmailInput.value = account.email || '';
        tokenModalInput.value = account.token || '';
        accountFormTitle.textContent = '编辑账户';
        tokenSaveBtn.textContent = '保存修改';
        accountResetBtn.style.display = 'inline-flex';
        setTimeout(() => accountNameInput.focus(), 0);
      }
  
      function persistAccounts() {
        // 每次账户变更都立即落盘，避免刷新丢失
        localStorage.setItem(STORAGE_ACCOUNTS, JSON.stringify(state.accounts));
        if (state.activeAccountId) {
          localStorage.setItem(STORAGE_ACTIVE_ACCOUNT, state.activeAccountId);
        }
      }
  
      function getActiveAccount() {
        return state.accounts.find((a) => a.id === state.activeAccountId) || null;
      }
  
      function normalizeEmail(value) {
        return String(value || '').trim().toLowerCase();
      }
  
      // 账户 UI：下拉框与弹窗列表
      function renderAccountSelect() {
        if (!state.accounts.length) {
          accountSelect.innerHTML = '<option value="">未配置账户</option>';
          return;
        }
  
        accountSelect.innerHTML = state.accounts.map((account) => {
          const selected = account.id === state.activeAccountId ? ' selected' : '';
          const label = account.email ? (account.name + ' (' + account.email + ')') : (account.name + ' (不过滤)');
          return '<option value="' + escapeHtml(account.id) + '"' + selected + '>' + escapeHtml(label) + '</option>';
        }).join('');
      }
  
      function renderAccountList() {
        if (!state.accounts.length) {
          accountListEl.innerHTML = '<div class="empty" style="padding:12px;">还没有账户，请先新增一个。</div>';
          return;
        }
  
        accountListEl.innerHTML = state.accounts.map((account) => {
          const isActive = account.id === state.activeAccountId;
          const badge = isActive ? '<span class="meta">当前</span>' : '';
          const emailText = account.email || '不过滤收件地址';
          return '<div class="account-row" data-account-id="' + escapeHtml(account.id) + '">' +
            '<div class="account-row-main">' +
              '<div class="account-name">' + escapeHtml(account.name) + ' ' + badge + '</div>' +
              '<div class="account-email">' + escapeHtml(emailText) + '</div>' +
            '</div>' +
            '<div style="display:flex;gap:6px;">' +
              '<button class="btn-secondary" data-action="edit">编辑</button>' +
              '<button class="btn-secondary" data-action="use">切换</button>' +
              '<button class="btn-secondary" data-action="delete">删除</button>' +
            '</div>' +
          '</div>';
        }).join('');
      }
  
      function applyAccountFilter(messages) {
        const account = getActiveAccount();
        if (!account) return [];
        const target = normalizeEmail(account.email);
        if (!target) return messages;
  
        return messages.filter((msg) => {
          const toValue = normalizeEmail(msg.to);
          return toValue.includes(target);
        });
      }
  
      function openTokenModal() {
        tokenModal.classList.add('show');
        tokenModal.setAttribute('aria-hidden', 'false');
        resetAccountForm();
        renderAccountList();
        tokenCancelBtn.style.display = 'inline-flex';
        setTimeout(() => accountNameInput.focus(), 0);
      }
  
      function closeTokenModal() {
        tokenModal.classList.remove('show');
        tokenModal.setAttribute('aria-hidden', 'true');
        resetAccountForm();
      }
  
      function setStatus(text, type='') {
        // type: '' | 'ok' | 'err'
        statusEl.textContent = text;
        statusEl.className = 'status ' + type;
      }
  
      function showValidationError(message) {
        setStatus(message, 'err');
        alert(message);
      }
  
      function authHeaders() {
        const token = getActiveAccount()?.token || '';
        if (!token) return {};
        // Worker 端按 Bearer Token 进行鉴权
        return { Authorization: 'Bearer ' + token };
      }
  
      async function api(path, init={}) {
        const res = await fetch(path, {
          ...init,
          headers: {
            'content-type': 'application/json',
            ...authHeaders(),
            ...(init.headers || {})
          }
        });
        if (!res.ok) {
          // 保留服务端原始错误文本，便于排查
          const msg = await res.text();
          throw new Error('[' + res.status + '] ' + msg);
        }
        return res.json();
      }
  
      function renderList() {
        const filteredMessages = applyAccountFilter(state.messages);
        countEl.textContent = filteredMessages.length + ' 封';
        if (!filteredMessages.length) {
          listEl.innerHTML = '<div class="empty">当前账户暂无邮件，或被收件地址过滤。</div>';
          return;
        }
  
        if (!filteredMessages.some((msg) => msg.id === state.currentId)) {
          // 若当前选中项被过滤掉，自动回退到第一封
          state.currentId = filteredMessages[0].id;
        }
  
        listEl.innerHTML = filteredMessages.map(msg => {
          const active = msg.id === state.currentId ? 'active' : '';
          return '<div class="item ' + active + '" data-id="' + msg.id + '">' +
            '<div class="subject">' + escapeHtml(msg.subject || '(No Subject)') + '</div>' +
            '<div class="meta">From: ' + escapeHtml(msg.from || '-') + '</div>' +
            '<div class="meta">At: ' + new Date(msg.receivedAt).toLocaleString() + '</div>' +
            '<div class="preview">' + escapeHtml((msg.preview || '').slice(0, 120)) + '</div>' +
          '</div>';
        }).join('');
  
        listEl.querySelectorAll('.item').forEach(el => {
          el.addEventListener('click', () => openMessage(el.dataset.id));
        });
      }
  
      // 邮件数据：刷新列表与加载详情
      async function refresh() {
        const account = getActiveAccount();
        if (!account) {
          // 未配置账户时，不发请求，直接渲染空态
          state.messages = [];
          state.currentId = null;
          renderList();
          detailEl.className = 'mail-body empty';
          detailEl.textContent = '请先在“账户设置”中新增账户';
          setStatus('未配置账户', 'err');
          return;
        }
  
        try {
          setStatus('正在刷新...', '');
          const data = await api('/api/messages');
          // 后端返回可能为空，统一回退到空数组
          state.messages = data.messages || [];
          renderList();
          if (state.currentId) {
            await openMessage(state.currentId, true);
          } else {
            detailEl.className = 'mail-body empty';
            detailEl.textContent = '请选择左侧邮件查看内容';
          }
          setStatus('刷新完成', 'ok');
        } catch (err) {
          setStatus('刷新失败: ' + err.message, 'err');
        }
      }
  
      async function openMessage(id, silent=false) {
        if (!id) return;
        try {
          state.currentId = id;
          renderList();
          const msg = await api('/api/messages/' + encodeURIComponent(id));
          detailEl.className = 'mail-body';
          detailEl.innerHTML =
            '<div class="mail-top">' +
              '<div><strong>' + escapeHtml(msg.subject || '(No Subject)') + '</strong></div>' +
              '<div class="meta">From: ' + escapeHtml(msg.from || '-') + '</div>' +
              '<div class="meta">To: ' + escapeHtml(msg.to || '-') + '</div>' +
              '<div class="meta">Size: ' + (msg.size || 0) + ' bytes</div>' +
              '<div class="meta">Received: ' + new Date(msg.receivedAt).toLocaleString() + '</div>' +
            '</div>' +
            '<div class="content">' + escapeHtml(msg.textBody || '(空正文)') + '</div>';
          if (!silent) setStatus('已加载邮件详情', 'ok');
        } catch (err) {
          detailEl.className = 'mail-body empty';
          detailEl.textContent = '邮件加载失败: ' + err.message;
          setStatus('详情加载失败: ' + err.message, 'err');
        }
      }
  
      async function deleteCurrent() {
        if (!state.currentId) return;
        try {
          const deletingId = state.currentId;
          await api('/api/messages/' + encodeURIComponent(deletingId), { method: 'DELETE' });
          // 本地同步删除，避免再次全量请求
          state.messages = state.messages.filter(m => m.id !== deletingId);
          state.currentId = state.messages[0]?.id || null;
          renderList();
          if (state.currentId) {
            await openMessage(state.currentId, true);
          } else {
            detailEl.className = 'mail-body empty';
            detailEl.textContent = '没有可显示的邮件';
          }
          setStatus('删除成功', 'ok');
        } catch (err) {
          setStatus('删除失败: ' + err.message, 'err');
        }
      }
  
      async function clearAll() {
        if (!confirm('确认清空所有邮件吗？')) return;
        try {
          await api('/api/clear', { method: 'POST', body: '{}' });
          state.messages = [];
          state.currentId = null;
          renderList();
          detailEl.className = 'mail-body empty';
          detailEl.textContent = '所有邮件已清空';
          setStatus('清空成功', 'ok');
        } catch (err) {
          setStatus('清空失败: ' + err.message, 'err');
        }
      }
  
      function escapeHtml(v) {
        return String(v)
          .replace(/&/g, '&amp;')
          .replace(/</g, '&lt;')
          .replace(/>/g, '&gt;')
          .replace(/"/g, '&quot;')
          .replace(/'/g, '&#39;');
      }
  
      // 表单校验：名称、邮箱、Token 及唯一性
      function validateNewAccount(name, email, token, editingAccountId='') {
        const normalizedName = name.trim();
        const normalizedEmail = normalizeEmail(email || '');
        const normalizedToken = token.trim();
  
        if (!normalizedName) return '请填写账户名称';
        if (normalizedName.length < 2 || normalizedName.length > 32) {
          return '账户名称长度需在 2-32 个字符之间';
        }
  
        if (!normalizedEmail) return '请填写收件地址';
  
        if (!normalizedToken) return '请填写 Dashboard Token';
  
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(normalizedEmail)) return '收件地址格式不正确';
  
        const nameExists = state.accounts.some((item) => item.id !== editingAccountId && item.name.trim().toLowerCase() === normalizedName.toLowerCase());
        if (nameExists) return '账户名称已存在，请使用其他名称';
  
        if (normalizedEmail) {
          const emailExists = state.accounts.some((item) => item.id !== editingAccountId && normalizeEmail(item.email) === normalizedEmail);
          if (emailExists) return '该收件地址已被其他账户使用';
        }
  
        return '';
      }
  
      async function ensureMailboxExists(email) {
        const normalizedEmail = normalizeEmail(email || '');
        try {
          // 提前校验邮箱是否可访问，减少失败提交
          const result = await api('/api/mailboxes/exists?address=' + encodeURIComponent(normalizedEmail));
          return !!result.exists;
        } catch (err) {
          showValidationError('邮箱存在性校验失败: ' + err.message);
          return false;
        }
      }
  
      async function saveTokenAndRefresh() {
        const name = accountNameInput.value.trim();
        const email = accountEmailInput.value.trim();
        const token = tokenModalInput.value.trim();
        const editingAccountId = state.editingAccountId || '';
  
        const validationError = validateNewAccount(name, email, token, editingAccountId);
        if (validationError) {
          showValidationError(validationError);
          return;
        }
  
        const mailboxExists = await ensureMailboxExists(email);
        if (!mailboxExists) {
          showValidationError('该收件地址不存在或当前账号无权限访问，请先确认邮箱路由已配置。');
          return;
        }
  
        if (editingAccountId) {
          // 编辑模式：覆盖原账户
          const index = state.accounts.findIndex((item) => item.id === editingAccountId);
          if (index < 0) {
            showValidationError('账户不存在或已删除，请重试');
            resetAccountForm();
            renderAccountList();
            return;
          }
  
          state.accounts[index] = {
            ...state.accounts[index],
            name,
            email,
            token,
          };
        } else {
          // 新增模式：创建新账户并切换为当前
          const account = {
            id: 'acc-' + Date.now() + '-' + Math.random().toString(36).slice(2, 7),
            name,
            email,
            token,
          };
  
          state.accounts.push(account);
          state.activeAccountId = account.id;
        }
  
        persistAccounts();
        renderAccountSelect();
        renderAccountList();
        resetAccountForm();
  
        closeTokenModal();
        setStatus(editingAccountId ? '账户已更新' : '账户已新增', 'ok');
        await refresh();
      }
  
      // 事件绑定：账户操作与邮件操作
      tokenSaveBtn.addEventListener('click', saveTokenAndRefresh);
      [accountNameInput, accountEmailInput, tokenModalInput].forEach((el) => el.addEventListener('keydown', (event) => {
        if (event.key === 'Enter') {
          saveTokenAndRefresh();
        }
      }));
  
      tokenCancelBtn.addEventListener('click', () => {
        closeTokenModal();
      });
  
      accountResetBtn.addEventListener('click', () => {
        resetAccountForm();
        setStatus('已取消编辑', 'ok');
      });
  
      manageAccountsBtn.addEventListener('click', () => {
        openTokenModal();
      });
  
      accountSelect.addEventListener('change', async () => {
        state.activeAccountId = accountSelect.value || null;
        state.currentId = null;
        persistAccounts();
        await refresh();
      });
  
      accountListEl.addEventListener('click', async (event) => {
        // 使用事件代理处理每行账户按钮
        const btn = event.target.closest('button[data-action]');
        if (!btn) return;
        const row = event.target.closest('.account-row');
        if (!row) return;
  
        const accountId = row.dataset.accountId;
        if (!accountId) return;
  
        const action = btn.dataset.action;
        if (action === 'edit') {
          startEditAccount(accountId);
          setStatus('正在编辑账户', 'ok');
          return;
        }
  
        if (action === 'use') {
          // 切换当前账户后立即刷新列表
          state.activeAccountId = accountId;
          state.currentId = null;
          persistAccounts();
          renderAccountSelect();
          renderAccountList();
          closeTokenModal();
          await refresh();
          return;
        }
  
        if (action === 'delete') {
          const target = state.accounts.find((a) => a.id === accountId);
          if (!target) return;
          // 删除前二次确认，避免误操作
          if (!confirm('确认删除账户：' + target.name + ' ?')) return;
  
          state.accounts = state.accounts.filter((a) => a.id !== accountId);
          if (state.editingAccountId === accountId) {
            resetAccountForm();
          }
          if (!state.accounts.length) {
            state.activeAccountId = null;
          } else if (state.activeAccountId === accountId) {
            state.activeAccountId = state.accounts[0].id;
          }
  
          persistAccounts();
          renderAccountSelect();
          renderAccountList();
          state.currentId = null;
          await refresh();
        }
      });
  
      $('refreshBtn').addEventListener('click', refresh);
      $('deleteBtn').addEventListener('click', deleteCurrent);
      $('clearBtn').addEventListener('click', clearAll);
  
      renderAccountSelect();
      if (!state.accounts.length) {
        openTokenModal();
      } else {
        refresh();
      }
  
      // 背景粒子：仅视觉增强，不参与业务状态
      (() => {
        const c = $('particles');
        const ctx = c.getContext('2d');
        const pts = [];
  
        function resize() {
          c.width = window.innerWidth;
          c.height = window.innerHeight;
        }
  
        function spawn() {
          // 保持粒子上限，避免每帧重复创建
          while (pts.length < 80) {
            pts.push({
              x: Math.random() * c.width,
              y: Math.random() * c.height,
              vx: (Math.random() - 0.5) * 0.35,
              vy: (Math.random() - 0.5) * 0.35,
              r: Math.random() * 1.8 + 0.6,
            });
          }
        }
  
        function step() {
          ctx.clearRect(0, 0, c.width, c.height);
          for (const p of pts) {
            p.x += p.vx;
            p.y += p.vy;
            if (p.x < -10) p.x = c.width + 10;
            if (p.x > c.width + 10) p.x = -10;
            if (p.y < -10) p.y = c.height + 10;
            if (p.y > c.height + 10) p.y = -10;
  
            ctx.beginPath();
            ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
            ctx.fillStyle = 'rgba(129, 154, 147, 0.38)';
            ctx.fill();
          }
  
          for (let i = 0; i < pts.length; i++) {
            for (let j = i + 1; j < pts.length; j++) {
              const a = pts[i];
              const b = pts[j];
              const dx = a.x - b.x;
              const dy = a.y - b.y;
              const d = Math.hypot(dx, dy);
              if (d < 120) {
                // 距离越近连线越明显
                const alpha = 1 - d / 120;
                ctx.strokeStyle = 'rgba(167, 146, 162,' + (alpha * 0.22).toFixed(3) + ')';
                ctx.lineWidth = 1;
                ctx.beginPath();
                ctx.moveTo(a.x, a.y);
                ctx.lineTo(b.x, b.y);
                ctx.stroke();
              }
            }
          }
  
          requestAnimationFrame(step);
        }
  
        window.addEventListener('resize', resize);
        resize();
        spawn();
        step();
      })();
  
}
