<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>بوابة العميل | تمام</title>
<style>
  :root{
    --ink:#1E1B16; --paper:#F4EFE3; --card:#FFFDF8; --line:#E6DFCE; --line-strong:#D8CFB8;
    --brass:#AD8A3F; --brass-light:#C9A968; --muted:#7A7360; --muted-2:#9A927C; --text:#2A261E;
    --red:#A6432E; --red-bg:#F4E6E1; --green:#2F6F4E; --green-bg:#E4F0EA; --radius:12px;
  }
  *{box-sizing:border-box;}
  body{margin:0; font-family:'Segoe UI', Tahoma, Arial, sans-serif; background:var(--paper); color:var(--text); min-height:100vh;}
  .hidden{display:none !important;}

  #login-screen{min-height:100vh; display:flex; align-items:center; justify-content:center; padding:20px;}
  .login-box{background:var(--card); border:1px solid var(--line); border-radius:16px; padding:36px 32px; width:100%; max-width:380px; box-shadow:0 10px 40px rgba(0,0,0,.08);}
  .login-box h1{font-size:20px; margin:0 0 4px; color:var(--ink);}
  .login-box p{font-size:12.5px; color:var(--muted); margin:0 0 24px;}
  .login-box label{display:block; font-size:12.5px; font-weight:600; margin-bottom:6px; color:var(--text);}
  .login-box input{width:100%; padding:11px 13px; border:1.3px solid var(--line-strong); border-radius:8px; font-size:13.5px; margin-bottom:16px; background:var(--paper); font-family:inherit;}
  .login-box input:focus{outline:none; border-color:var(--brass); background:var(--card);}
  .login-box button{width:100%; padding:12px; background:var(--ink); color:#F3EFE2; border:none; border-radius:9px; font-size:14px; font-weight:700; cursor:pointer; font-family:inherit;}
  .login-box button:hover{background:#332D22;}
  .login-error{background:var(--red-bg); color:var(--red); border:1px solid #E8C7BC; padding:9px 13px; border-radius:8px; font-size:12px; margin-bottom:14px; display:none;}

  #app-screen{display:none; min-height:100vh; flex-direction:column;}
  header{background:var(--card); border-bottom:1px solid var(--line); padding:14px 22px; display:flex; align-items:center; justify-content:space-between;}
  header .brand{font-weight:800; color:var(--ink); font-size:15px;}
  header .brand span{color:var(--brass); font-weight:400; font-size:12px; margin-inline-start:8px;}
  header .who{display:flex; align-items:center; gap:12px;}
  header .who .nm{font-size:12.5px; font-weight:700;}
  header .who .jt{font-size:10.5px; color:var(--muted);}
  header button.logout{background:none; border:1px solid var(--line-strong); border-radius:8px; padding:7px 14px; font-size:11.5px; cursor:pointer; color:var(--muted); font-family:inherit;}
  header button.logout:hover{border-color:var(--red); color:var(--red);}

  .tab-strip{display:flex; gap:4px; padding:10px 22px 0; background:var(--card); border-bottom:1px solid var(--line);}
  .tab-strip .tab{padding:10px 18px; font-size:13px; font-weight:600; color:var(--muted); cursor:pointer; border-bottom:2.5px solid transparent;}
  .tab-strip .tab.active{color:var(--ink); border-bottom-color:var(--brass);}

  .content{flex:1; padding:24px; max-width:960px; margin:0 auto; width:100%;}
  .panel{background:var(--card); border:1px solid var(--line); border-radius:var(--radius); padding:20px 22px; margin-bottom:16px;}
  .panel h3{margin:0 0 14px; font-size:14px; color:var(--ink);}
  .stat-row{display:grid; grid-template-columns:repeat(3,1fr); gap:12px; margin-bottom:18px;}
  .stat-card{background:var(--card); border:1px solid var(--line); border-radius:10px; padding:16px; text-align:center;}
  .stat-card .num{font-size:22px; font-weight:800; color:var(--ink);}
  .stat-card .lbl{font-size:11px; color:var(--muted); margin-top:4px;}
  table{width:100%; border-collapse:collapse;}
  th{text-align:right; font-size:11px; color:var(--muted); font-weight:600; padding:8px 10px; border-bottom:1px solid var(--line);}
  td{padding:10px; font-size:12.5px; border-bottom:1px solid var(--line);}
  .badge{display:inline-flex; padding:3px 10px; border-radius:12px; font-size:10.5px; font-weight:700; align-items:center; gap:5px;}
  .badge.ok{background:var(--green-bg); color:var(--green);}
  .badge.flag{background:#FBEFE0; color:#B5762C;}
  .empty-hint{text-align:center; color:var(--muted-2); font-size:12.5px; padding:30px;}
  .btn{padding:8px 15px; border-radius:8px; border:1px solid var(--line-strong); background:var(--card); font-size:12px; cursor:pointer; font-family:inherit; color:var(--text);}
  .btn.dark{background:var(--ink); color:#F3EFE2; border-color:var(--ink);}

  .chat-wrap{display:flex; flex-direction:column; height:calc(100vh - 230px); min-height:400px;}
  .chat-thread{flex:1; overflow-y:auto; background:var(--paper); border:1px solid var(--line); border-radius:var(--radius) var(--radius) 0 0; padding:16px; display:flex; flex-direction:column; gap:12px;}
  .msg-wrap{display:flex; flex-direction:column; max-width:64%;}
  .msg-wrap.mine{align-self:flex-start; align-items:flex-start;}
  .msg-wrap.theirs{align-self:flex-end; align-items:flex-end;}
  .msg-sender{font-size:10.5px; font-weight:700; color:var(--brass); margin-bottom:4px;}
  .bubble{padding:9px 13px; border-radius:12px; font-size:12.8px; line-height:1.6;}
  .bubble.mine{background:var(--ink); color:#F3EFE2; border-bottom-right-radius:3px;}
  .bubble.theirs{background:var(--card); border:1px solid var(--line); border-bottom-left-radius:3px;}
  .bubble .item-lbl{font-size:10px; font-weight:700; opacity:.75; margin-bottom:4px;}
  .bubble .time{font-size:9px; opacity:.65; margin-top:4px;}
  .bubble .attach{display:flex; align-items:center; gap:6px; margin-top:6px; padding:6px 9px; border-radius:8px; background:rgba(255,255,255,.08); font-size:11px; cursor:pointer;}
  .bubble.theirs .attach{background:var(--paper);}
  .file-sep{text-align:center; font-size:10px; color:var(--brass); background:var(--paper); border:1px solid var(--line); border-radius:12px; padding:4px 14px; margin:6px auto; width:fit-content;}
  .chat-picker{display:flex; gap:8px; padding:8px 12px; background:var(--paper); border:1px solid var(--line); border-top:none;}
  .chat-picker select{flex:1; font-size:11px; padding:6px 8px; border:1.2px solid var(--line-strong); border-radius:6px; background:var(--card);}
  .composer{display:flex; align-items:center; gap:8px; padding:10px 12px; background:var(--card); border:1px solid var(--line); border-top:none; border-radius:0 0 var(--radius) var(--radius);}
  .composer input[type=text]{flex:1; border:1.3px solid var(--line-strong); border-radius:20px; padding:9px 16px; background:var(--paper); font-size:12.8px; font-family:inherit;}
  .icon-btn{width:34px; height:34px; border-radius:50%; display:flex; align-items:center; justify-content:center; cursor:pointer; color:var(--muted); border:1px solid var(--line-strong); background:var(--card); flex-shrink:0;}
  .icon-btn svg{width:16px; height:16px;}
  .file-preview{font-size:10.5px; color:var(--brass); background:var(--paper); padding:4px 10px; border-radius:14px; display:flex; align-items:center; gap:6px;}
  .toast{position:fixed; bottom:24px; left:50%; transform:translateX(-50%); background:var(--ink); color:#F3EFE2; padding:11px 22px; border-radius:10px; font-size:12.5px; z-index:999; opacity:0; transition:opacity .25s; pointer-events:none;}
  .toast.show{opacity:1;}

  @media (max-width:700px){
    .stat-row{grid-template-columns:1fr;}
    .content{padding:14px;}
    header{padding:12px 14px;}
  }
</style>
</head>
<body>

<div id="login-screen">
  <div class="login-box">
    <h1>بوابة العميل</h1>
    <p>سجّل الدخول لمتابعة ملفك مع مكتب المراجعة</p>
    <div class="login-error" id="login-error"></div>
    <label>اسم المستخدم</label>
    <input id="login-username" placeholder="اسم المستخدم">
    <label>كلمة المرور</label>
    <input id="login-password" type="password" placeholder="••••••••" onkeydown="if(event.key==='Enter') doLogin();">
    <button onclick="doLogin()">تسجيل الدخول</button>
  </div>
</div>

<div id="app-screen">
  <header>
    <div class="brand">تمام <span id="header-client-name"></span></div>
    <div class="who">
      <div>
        <div class="nm" id="header-emp-name">—</div>
        <div class="jt" id="header-emp-title">—</div>
      </div>
      <button class="logout" onclick="doLogout()">تسجيل الخروج</button>
    </div>
  </header>

  <div class="tab-strip">
    <div class="tab active" onclick="switchPortalTab(this,'home')">الرئيسية</div>
    <div class="tab" onclick="switchPortalTab(this,'chat')">الدردشة</div>
    <div class="tab" onclick="switchPortalTab(this,'requirements')">المتطلبات</div>
  </div>

  <div class="content">
    <div class="ptab" id="ptab-home">
      <div class="stat-row">
        <div class="stat-card"><div class="num" id="stat-files">0</div><div class="lbl">ملفات التدقيق</div></div>
        <div class="stat-card"><div class="num" id="stat-req-pending">0</div><div class="lbl">متطلبات بانتظارك</div></div>
        <div class="stat-card"><div class="num" id="stat-req-total">0</div><div class="lbl">إجمالي المتطلبات</div></div>
      </div>
      <div class="panel">
        <h3>ملفات التدقيق الخاصة بكم</h3>
        <table>
          <thead><tr><th>اسم الملف</th><th>نهاية الفترة</th><th>الحالة</th></tr></thead>
          <tbody id="home-files-tbody"><tr><td colspan="3" class="empty-hint">جارٍ التحميل...</td></tr></tbody>
        </table>
      </div>
    </div>

    <div class="ptab" id="ptab-chat" style="display:none;">
      <div class="chat-wrap">
        <div class="chat-thread" id="portal-chat-thread"></div>
        <div class="chat-picker">
          <select id="portal-chat-file" onchange="onPortalChatFileChange()"></select>
        </div>
        <div class="composer">
          <input type="file" id="portal-chat-file-input" style="display:none;" onchange="onPortalFileSelected(this)">
          <span class="icon-btn" title="إرفاق ملف" onclick="document.getElementById('portal-chat-file-input').click()">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21.44 11.05l-9.19 9.19a5 5 0 01-7.07-7.07l9.19-9.19a3.5 3.5 0 015 5l-9.2 9.19a1.5 1.5 0 01-2.12-2.12l8.49-8.48"/></svg>
          </span>
          <div class="file-preview" id="portal-file-preview" style="display:none;"></div>
          <input type="text" id="portal-chat-input" placeholder="اكتب رسالتك..." onkeydown="if(event.key==='Enter') sendPortalMessage();">
          <button class="btn dark" onclick="sendPortalMessage()">إرسال</button>
        </div>
      </div>
    </div>

    <div class="ptab" id="ptab-requirements" style="display:none;">
      <div class="panel">
        <h3>المتطلبات المطلوبة منكم</h3>
        <table>
          <thead><tr><th>المتطلب</th><th>الملف</th><th>الحالة</th><th></th></tr></thead>
          <tbody id="req-tbody"><tr><td colspan="4" class="empty-hint">جارٍ التحميل...</td></tr></tbody>
        </table>
      </div>
    </div>
  </div>
</div>

<div class="toast" id="toast"></div>

<script>
let TOKEN = localStorage.getItem('portal_token') || null;
let ME = JSON.parse(localStorage.getItem('portal_me') || 'null');
let PENDING_ATTACH = null;

function showToast(msg){
  const t = document.getElementById('toast');
  t.textContent = msg; t.classList.add('show');
  setTimeout(()=>t.classList.remove('show'), 2600);
}
function escapeHtml(s){ const d=document.createElement('div'); d.textContent=s||''; return d.innerHTML; }
function timeAgo(iso){ return new Date(iso).toLocaleString('ar-SA', {hour:'2-digit', minute:'2-digit', day:'2-digit', month:'2-digit'}); }

async function apiFetch(path, options={}){
  const headers = Object.assign({'Content-Type':'application/json'}, options.headers||{});
  if(TOKEN) headers['Authorization'] = 'Bearer '+TOKEN;
  const res = await fetch(path, Object.assign({}, options, {headers}));
  if(res.status === 401){ doLogout(); throw new Error('انتهت الجلسة'); }
  const data = await res.json().catch(()=>({}));
  if(!res.ok) throw new Error(data.message || 'حدث خطأ');
  return data;
}

async function doLogin(){
  const username = document.getElementById('login-username').value.trim();
  const password = document.getElementById('login-password').value;
  const errBox = document.getElementById('login-error');
  errBox.style.display = 'none';
  if(!username || !password){ errBox.textContent='عبّئ اسم المستخدم وكلمة المرور'; errBox.style.display='block'; return; }
  try{
    const data = await apiFetch('/api/portal/login', {method:'POST', body: JSON.stringify({username, password})});
    TOKEN = data.token;
    ME = data;
    localStorage.setItem('portal_token', TOKEN);
    localStorage.setItem('portal_me', JSON.stringify(ME));
    showApp();
  }catch(e){ errBox.textContent = e.message; errBox.style.display = 'block'; }
}
function doLogout(){
  TOKEN = null; ME = null;
  localStorage.removeItem('portal_token');
  localStorage.removeItem('portal_me');
  document.getElementById('app-screen').style.display = 'none';
  document.getElementById('login-screen').style.display = 'flex';
}
async function showApp(){
  document.getElementById('login-screen').style.display = 'none';
  document.getElementById('app-screen').style.display = 'flex';
  document.getElementById('header-client-name').textContent = '— ' + (ME.clientName||'');
  document.getElementById('header-emp-name').textContent = ME.fullName || '';
  document.getElementById('header-emp-title').textContent = ME.jobTitle || '';
  loadHome();
}

function switchPortalTab(el, key){
  document.querySelectorAll('.tab-strip .tab').forEach(t=>t.classList.remove('active'));
  el.classList.add('active');
  document.querySelectorAll('.ptab').forEach(p=>p.style.display='none');
  document.getElementById('ptab-'+key).style.display = '';
  if(key==='chat') loadPortalChat();
  if(key==='requirements') loadPortalRequirements();
}

async function loadHome(){
  try{
    const data = await apiFetch('/api/portal/dashboard');
    document.getElementById('stat-files').textContent = data.files.length;
    document.getElementById('stat-req-pending').textContent = data.requirementStats.pending;
    document.getElementById('stat-req-total').textContent = data.requirementStats.total;
    const tbody = document.getElementById('home-files-tbody');
    tbody.innerHTML = data.files.length ? data.files.map(f=>`
      <tr><td><b>${escapeHtml(f.name)}</b></td><td>${f.period_end||'—'}</td>
      <td><span class="badge ok">${f.status||'—'}</span></td></tr>`).join('')
      : '<tr><td colspan="3" class="empty-hint">لا توجد ملفات تدقيق بعد</td></tr>';
    const sel = document.getElementById('portal-chat-file');
    sel.innerHTML = data.files.map(f=>`<option value="${f.id}">📁 ${escapeHtml(f.name)}</option>`).join('') || '<option value="">لا توجد ملفات</option>';
  }catch(e){ showToast('تعذّر التحميل: '+e.message); }
}

async function loadPortalRequirements(){
  const tbody = document.getElementById('req-tbody');
  try{
    const rows = await apiFetch('/api/portal/requirements');
    tbody.innerHTML = rows.length ? rows.map(r=>`
      <tr><td>${escapeHtml(r.title)}</td><td>${r.client_files?escapeHtml(r.client_files.name):'—'}</td>
      <td><span class="badge ${r.is_fulfilled?'ok':'flag'}">${r.is_fulfilled?'تم الإرفاق':'بانتظار الإرفاق'}</span></td>
      <td>${!r.is_fulfilled ? `<button class="btn dark" onclick="openFulfillPicker('${r.id}')">إرفاق الملف</button>` : ''}</td></tr>`).join('')
      : '<tr><td colspan="4" class="empty-hint">لا توجد متطلبات حاليًا</td></tr>';
  }catch(e){ tbody.innerHTML = `<tr><td colspan="4" class="empty-hint">تعذّر التحميل: ${e.message}</td></tr>`; }
}
function openFulfillPicker(reqId){
  const input = document.createElement('input');
  input.type = 'file';
  input.onchange = async () => {
    const file = input.files[0];
    if(!file) return;
    if(file.size > 8*1024*1024){ showToast('الملف كبير جدًا (الحد 8 ميجا)'); return; }
    const reader = new FileReader();
    reader.onload = async () => {
      try{
        await apiFetch('/api/portal/requirements/'+reqId+'/fulfill', {method:'POST', body: JSON.stringify({
          attachment_name: file.name, attachment_mime: file.type, attachment_data: reader.result
        })});
        showToast('تم إرفاق الملف بنجاح');
        loadPortalRequirements();
        loadHome();
      }catch(e){ showToast('تعذّر الإرفاق: '+e.message); }
    };
    reader.readAsDataURL(file);
  };
  input.click();
}

async function loadPortalChat(){
  const container = document.getElementById('portal-chat-thread');
  container.innerHTML = '<div class="empty-hint">جارٍ التحميل...</div>';
  try{
    const msgs = await apiFetch('/api/portal/chat');
    let lastFile = null;
    container.innerHTML = msgs.length ? msgs.map(m=>{
      let sep = '';
      if(m.client_files && m.client_files.name && m.client_file_id !== lastFile){
        sep = `<div class="file-sep">📁 ${escapeHtml(m.client_files.name)}</div>`;
        lastFile = m.client_file_id;
      }
      return sep + portalBubbleHtml(m);
    }).join('') : '<div class="empty-hint">لا توجد رسائل بعد — ابدأ المحادثة</div>';
    container.scrollTop = container.scrollHeight;
  }catch(e){ container.innerHTML = `<div class="empty-hint">تعذّر التحميل: ${e.message}</div>`; }
}
function portalBubbleHtml(m){
  const mine = !!m.sender_client_employee_id && m.sender_client_employee_id === ME.employeeId;
  let nm = 'فريق المراجعة';
  if(m.sender_client_employee_id && m.client_employees) nm = m.client_employees.full_name + (m.client_employees.job_title?' — '+m.client_employees.job_title:'');
  else if(m.users) nm = ((m.users.first_name_ar||'')+' '+(m.users.last_name_ar||'')).trim() + (m.users.roles?' — '+m.users.roles.name_ar:'');
  let attachHtml = '';
  if(m.attachment_data){
    const isImg = (m.attachment_mime||'').startsWith('image/');
    attachHtml = isImg
      ? `<div class="attach" onclick="window.open('${m.attachment_data}','_blank')">📎 ${escapeHtml(m.attachment_name||'صورة')}</div>`
      : `<a class="attach" href="${m.attachment_data}" download="${escapeHtml(m.attachment_name||'file')}" style="color:inherit; text-decoration:none;">📎 ${escapeHtml(m.attachment_name||'مرفق')}</a>`;
  }
  const itemLbl = (m.wp_main_items && m.wp_main_items.title) ? `<div class="item-lbl">📎 ${escapeHtml(m.wp_main_items.title)}</div>` : '';
  return `<div class="msg-wrap ${mine?'mine':'theirs'}">
    <div class="msg-sender">${escapeHtml(nm)}</div>
    <div class="bubble ${mine?'mine':'theirs'}">
      ${itemLbl}
      ${m.body ? `<div>${escapeHtml(m.body)}</div>` : ''}
      ${attachHtml}
      <div class="time">${timeAgo(m.created_at)}</div>
    </div>
  </div>`;
}
function onPortalChatFileChange(){}
function onPortalFileSelected(input){
  const file = input.files[0];
  if(!file) return;
  if(file.size > 8*1024*1024){ showToast('الملف كبير جدًا (الحد 8 ميجا)'); input.value=''; return; }
  const reader = new FileReader();
  reader.onload = () => {
    PENDING_ATTACH = { name:file.name, mime:file.type, data:reader.result };
    const p = document.getElementById('portal-file-preview');
    p.style.display = 'flex';
    p.innerHTML = `📎 ${escapeHtml(file.name)} <span onclick="PENDING_ATTACH=null; document.getElementById('portal-file-preview').style.display='none'; document.getElementById('portal-chat-file-input').value='';" style="cursor:pointer; color:var(--red); font-weight:700; margin-inline-start:6px;">✕</span>`;
  };
  reader.readAsDataURL(file);
}
async function sendPortalMessage(){
  const input = document.getElementById('portal-chat-input');
  const text = input.value.trim();
  const fileSel = document.getElementById('portal-chat-file');
  if(!text && !PENDING_ATTACH) return;
  if(!fileSel.value){ showToast('اختر ملف التدقيق أولًا'); return; }
  const payload = { body: text || null, client_file_id: fileSel.value };
  if(PENDING_ATTACH){ payload.attachment_name = PENDING_ATTACH.name; payload.attachment_mime = PENDING_ATTACH.mime; payload.attachment_data = PENDING_ATTACH.data; }
  try{
    await apiFetch('/api/portal/chat', {method:'POST', body: JSON.stringify(payload)});
    input.value = '';
    PENDING_ATTACH = null;
    document.getElementById('portal-file-preview').style.display = 'none';
    document.getElementById('portal-chat-file-input').value = '';
    loadPortalChat();
  }catch(e){ showToast('تعذّر الإرسال: '+e.message); }
}

(async function init(){
  if(!TOKEN || !ME){ doLogout(); return; }
  try{
    await apiFetch('/api/portal/dashboard');
    showApp();
  }catch(e){ doLogout(); }
})();
</script>
</body>
</html>
