// ============================================================================
// خادم "تمام" — Node.js / Express
// يخدم الواجهة الثابتة، ويوفّر API حقيقي متعدد المكاتب (Multi-tenant):
// المستخدم يسجّل دخوله برمز مكتبه + اسم المستخدم + كلمة المرور، والسيرفر
// يحدّد شركته (company_id) ديناميكيًا من قاعدة البيانات — وليس من قيمة ثابتة.
// بهذا يقدر عدد غير محدود من المكاتب يستخدمون نفس النشر (Deployment) نفسه.
// ============================================================================

const express = require('express');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { createClient } = require('@supabase/supabase-js');
const ExcelJS = require('exceljs');

const app = express();
app.use(express.json({ limit: '15mb' }));

const PORT = process.env.PORT || 3000;
const SESSION_SECRET = process.env.SESSION_SECRET;
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

if (!SESSION_SECRET) {
  console.warn('تحذير: SESSION_SECRET غير مضبوط — استخدم قيمة سرّية عشوائية على رندر (وليس هذه الافتراضية).');
}
if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
  console.warn('تحذير: SUPABASE_URL أو SUPABASE_SERVICE_ROLE_KEY غير مضبوطين — كل نقاط API الحقيقية سترفض الطلبات.');
}

// عميل Supabase بصلاحية service_role — يُستخدم داخل السيرفر فقط، ولا يصل للمتصفح أبدًا
const supabaseAdmin = (SUPABASE_URL && SUPABASE_SERVICE_ROLE_KEY)
  ? createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)
  : null;

function requireSupabase(res) {
  if (!supabaseAdmin) {
    res.status(503).json({ message: 'السيرفر غير متصل بقاعدة البيانات بعد — تحقق من SUPABASE_URL و SUPABASE_SERVICE_ROLE_KEY' });
    return null;
  }
  return supabaseAdmin;
}

// ---------------------------------------------------------------------------
// المصادقة: التحقق من رمز الجلسة (JWT) المُرسل بترويسة Authorization: Bearer
// ---------------------------------------------------------------------------
function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ message: 'يلزم تسجيل الدخول' });
  try {
    const payload = jwt.verify(token, SESSION_SECRET || 'dev-insecure-secret-change-me');
    req.session = payload; // { companyId, userId, role, username }
    next();
  } catch (e) {
    return res.status(401).json({ message: 'الجلسة منتهية أو غير صالحة، سجّل الدخول مجددًا' });
  }
}

function signSession(payload) {
  return jwt.sign(payload, SESSION_SECRET || 'dev-insecure-secret-change-me', { expiresIn: '12h' });
}

const ROLE_LABELS = {
  partner: 'شريك', quality: 'فاحص جودة ارتباط', review_manager: 'مدير مراجعة',
  manager: 'مدير', senior_auditor: 'مراجع حسابات أول', auditor: 'مراجع حسابات',
  admin_assistant: 'مساعد إداري',
};

// ---------------------------------------------------------------------------
// تسجيل الدخول: رمز المكتب + اسم المستخدم + كلمة المرور
// ---------------------------------------------------------------------------
app.post('/api/login', async (req, res) => {
  const sb = requireSupabase(res); if (!sb) return;
  const { companyCode, username, password } = req.body || {};
  if (!companyCode || !username || !password) {
    return res.status(400).json({ message: 'عبّئ رمز المكتب واسم المستخدم وكلمة المرور' });
  }

  const { data: company, error: companyErr } = await sb
    .from('companies')
    .select('id, name_ar, is_active, subscription_end')
    .ilike('code', companyCode.trim())
    .maybeSingle();

  if (companyErr) return res.status(500).json({ message: 'خطأ بالخادم أثناء التحقق من المكتب' });
  if (!company) return res.status(401).json({ message: 'رمز المكتب غير صحيح' });

  const today = new Date().toISOString().slice(0, 10);
  if (!company.is_active || company.subscription_end < today) {
    return res.status(403).json({ message: 'اشتراك هذا المكتب منتهٍ أو معطّل — تواصل مع الدعم' });
  }

  const { data: user, error: userErr } = await sb
    .from('users')
    .select('id, first_name_ar, last_name_ar, role_id, username, password_hash, is_active, roles(code)')
    .eq('company_id', company.id)
    .eq('username', username.trim())
    .maybeSingle();

  if (userErr) return res.status(500).json({ message: 'خطأ بالخادم أثناء التحقق من المستخدم' });
  if (!user || !user.is_active) return res.status(401).json({ message: 'اسم المستخدم أو كلمة المرور غير صحيحة' });

  const passwordOk = await bcrypt.compare(password, user.password_hash || '');
  if (!passwordOk) return res.status(401).json({ message: 'اسم المستخدم أو كلمة المرور غير صحيحة' });

  await sb.from('users').update({ last_login_at: new Date().toISOString() }).eq('id', user.id);

  const roleCode = user.roles ? user.roles.code : null;
  const token = signSession({ companyId: company.id, userId: user.id, role: roleCode, username: user.username });

  res.json({
    token,
    companyId: company.id,
    companyName: company.name_ar,
    userId: user.id,
    role: roleCode,
    roleLabel: ROLE_LABELS[roleCode] || roleCode,
    username: user.username,
    fullName: `${user.first_name_ar} ${user.last_name_ar}`,
  });
});

// ---------------------------------------------------------------------------
// إنشاء مكتب جديد (حساب شركة جديدة) + أول مستخدم فيه (الشريك المسؤول)
// ---------------------------------------------------------------------------
app.post('/api/signup', async (req, res) => {
  const sb = requireSupabase(res); if (!sb) return;
  const { nameAr, nameEn, code, email, adminName, adminUsername, adminPassword } = req.body || {};
  if (!nameAr || !code || !adminUsername || !adminPassword) {
    return res.status(400).json({ message: 'عبّئ اسم المكتب ورمزه وبيانات الشريك المسؤول' });
  }

  const { data: existing } = await sb.from('companies').select('id').ilike('code', code.trim()).maybeSingle();
  if (existing) return res.status(409).json({ message: 'رمز المكتب هذا مستخدم مسبقًا، اختر رمزًا آخر' });

  const subscriptionEnd = new Date();
  subscriptionEnd.setDate(subscriptionEnd.getDate() + 30); // فترة تجريبية 30 يومًا

  const { data: company, error: companyErr } = await sb
    .from('companies')
    .insert({
      code: code.trim().toUpperCase(),
      name_ar: nameAr, name_en: nameEn || null, email: email || null,
      subscription_start: new Date().toISOString().slice(0, 10),
      subscription_end: subscriptionEnd.toISOString().slice(0, 10),
      is_active: true,
    })
    .select()
    .single();
  if (companyErr) return res.status(500).json({ message: 'تعذّر إنشاء المكتب: ' + companyErr.message });

  const { data: partnerRole } = await sb.from('roles').select('id, code').eq('code', 'partner').single();
  const passwordHash = await bcrypt.hash(adminPassword, 10);
  const [firstName, ...rest] = (adminName || 'الشريك المسؤول').split(' ');

  const { data: user, error: userErr } = await sb
    .from('users')
    .insert({
      company_id: company.id,
      role_id: partnerRole ? partnerRole.id : null,
      first_name_ar: firstName, last_name_ar: rest.join(' ') || '-',
      username: adminUsername.trim(), email: email || null,
      password_hash: passwordHash, is_active: true,
    })
    .select()
    .single();
  if (userErr) return res.status(500).json({ message: 'تعذّر إنشاء المستخدم الأول: ' + userErr.message });

  const token = signSession({ companyId: company.id, userId: user.id, role: 'partner', username: user.username });
  res.json({
    token, companyId: company.id, companyName: company.name_ar,
    userId: user.id, role: 'partner', username: user.username, fullName: adminName,
  });
});

// ---------------------------------------------------------------------------
// دليل الحسابات
// ---------------------------------------------------------------------------
app.get('/api/chart-of-accounts', requireAuth, async (req, res) => {
  const sb = requireSupabase(res); if (!sb) return;
  const { data, error } = await sb.from('chart_of_accounts')
    .select('id,code,name_ar,level,parent_id,language,deposit_account_id,statement_code,is_active')
    .eq('company_id', req.session.companyId)
    .order('code');
  if (error) return res.status(500).json({ message: error.message });
  res.json(data);
});

app.post('/api/chart-of-accounts', requireAuth, async (req, res) => {
  const sb = requireSupabase(res); if (!sb) return;
  const payload = { ...req.body, company_id: req.session.companyId }; // company_id يُفرض من الجلسة دائمًا
  const { data, error } = await sb.from('chart_of_accounts').insert(payload).select().single();
  if (error) return res.status(500).json({ message: error.message });
  res.json(data);
});

// ---------------------------------------------------------------------------
// أوراق العمل: مجموعات + أوراق رئيسية (قائمة كاملة لهذا المكتب)
// ---------------------------------------------------------------------------
app.get('/api/working-papers', requireAuth, async (req, res) => {
  const sb = requireSupabase(res); if (!sb) return;
  const [{ data: groups, error: e1 }, { data: mains, error: e2 }] = await Promise.all([
    sb.from('wp_groups').select('*').eq('company_id', req.session.companyId).order('code'),
    sb.from('wp_main_items').select('*').eq('company_id', req.session.companyId).order('code'),
  ]);
  if (e1 || e2) return res.status(500).json({ message: (e1 || e2).message });
  res.json({ groups, mains });
});

// يحفظ أهداف "الظهور الخاص" لأي كيان (مجموعة/رئيسي/فرعي) — يحذف القديم ثم يدرج الجديد
async function saveVisibilityTargets(sb, entityType, entityId, targets) {
  await sb.from('wp_visibility_targets').delete().eq('entity_type', entityType).eq('entity_id', entityId);
  const rows = (Array.isArray(targets) ? targets : [])
    .filter(t => t && (t.client_type_id || t.sector_id))
    .map(t => ({ entity_type: entityType, entity_id: entityId, client_type_id: t.client_type_id || null, sector_id: t.sector_id || null }));
  if (rows.length) {
    const { error } = await sb.from('wp_visibility_targets').insert(rows);
    if (error) throw error;
  }
}

app.get('/api/wp-groups/:id', requireAuth, async (req, res) => {
  const sb = requireSupabase(res); if (!sb) return;
  const { data: group, error } = await sb.from('wp_groups').select('*')
    .eq('id', req.params.id).eq('company_id', req.session.companyId).maybeSingle();
  if (error) return res.status(500).json({ message: error.message });
  if (!group) return res.status(404).json({ message: 'المجموعة غير موجودة' });
  const { data: targets } = await sb.from('wp_visibility_targets').select('*').eq('entity_type', 'group').eq('entity_id', req.params.id);
  res.json({ group, targets: targets || [] });
});

app.post('/api/wp-groups', requireAuth, async (req, res) => {
  const sb = requireSupabase(res); if (!sb) return;
  const payload = { code: req.body.code, name: req.body.name, visibility: req.body.visibility, company_id: req.session.companyId };
  if (req.body.coa_code) {
    const { data: coaAccount } = await sb.from('chart_of_accounts').select('id')
      .eq('company_id', req.session.companyId).eq('code', req.body.coa_code).maybeSingle();
    if (coaAccount) payload.coa_account_id = coaAccount.id;
  }
  const { data, error } = await sb.from('wp_groups').insert(payload).select().single();
  if (error) return res.status(500).json({ message: error.message });
  try { await saveVisibilityTargets(sb, 'group', data.id, req.body.visibility_targets); }
  catch (e) { return res.status(500).json({ message: e.message }); }
  res.json(data);
});

app.put('/api/wp-groups/:id', requireAuth, async (req, res) => {
  const sb = requireSupabase(res); if (!sb) return;
  const { data: existing } = await sb.from('wp_groups').select('id').eq('id', req.params.id).eq('company_id', req.session.companyId).maybeSingle();
  if (!existing) return res.status(404).json({ message: 'المجموعة غير موجودة' });
  const payload = { code: req.body.code, name: req.body.name, visibility: req.body.visibility, is_active: req.body.is_active !== false };
  if (req.body.coa_code !== undefined) {
    if (req.body.coa_code) {
      const { data: coaAccount } = await sb.from('chart_of_accounts').select('id')
        .eq('company_id', req.session.companyId).eq('code', req.body.coa_code).maybeSingle();
      payload.coa_account_id = coaAccount ? coaAccount.id : null;
    } else {
      payload.coa_account_id = null;
    }
  }
  const { data, error } = await sb.from('wp_groups').update(payload).eq('id', req.params.id).select().single();
  if (error) return res.status(500).json({ message: error.message });
  try { await saveVisibilityTargets(sb, 'group', req.params.id, req.body.visibility_targets); }
  catch (e) { return res.status(500).json({ message: e.message }); }
  res.json(data);
});

app.delete('/api/wp-groups/:id', requireAuth, async (req, res) => {
  const sb = requireSupabase(res); if (!sb) return;
  const { data: existing } = await sb.from('wp_groups').select('id').eq('id', req.params.id).eq('company_id', req.session.companyId).maybeSingle();
  if (!existing) return res.status(404).json({ message: 'المجموعة غير موجودة' });
  const { error } = await sb.from('wp_groups').delete().eq('id', req.params.id);
  if (error) return res.status(500).json({ message: 'تعذّر حذف المجموعة (تأكد من عدم وجود أوراق رئيسية تابعة لها): ' + error.message });
  await sb.from('wp_visibility_targets').delete().eq('entity_type', 'group').eq('entity_id', req.params.id);
  res.json({ ok: true });
});

app.get('/api/wp-main-items/:id', requireAuth, async (req, res) => {
  const sb = requireSupabase(res); if (!sb) return;
  const { data: main, error: e1 } = await sb.from('wp_main_items').select('*')
    .eq('id', req.params.id).eq('company_id', req.session.companyId).maybeSingle();
  if (e1) return res.status(500).json({ message: e1.message });
  if (!main) return res.status(404).json({ message: 'الورقة غير موجودة' });
  const { data: subs, error: e2 } = await sb.from('wp_sub_items').select('*')
    .eq('main_item_id', req.params.id).order('sort_order');
  if (e2) return res.status(500).json({ message: e2.message });
  const { data: targets } = await sb.from('wp_visibility_targets').select('*').eq('entity_type', 'main').eq('entity_id', req.params.id);
  res.json({ main, subs, targets: targets || [] });
});

app.post('/api/wp-main-items', requireAuth, async (req, res) => {
  const sb = requireSupabase(res); if (!sb) return;
  // تأكد أن المجموعة تتبع نفس مكتب المستخدم الحالي قبل الإدراج
  const { data: group } = await sb.from('wp_groups').select('id')
    .eq('id', req.body.group_id).eq('company_id', req.session.companyId).maybeSingle();
  if (!group) return res.status(400).json({ message: 'المجموعة غير موجودة أو لا تتبع مكتبك' });
  const { visibility_targets, ...rest } = req.body;
  const payload = { ...rest, company_id: req.session.companyId };
  const { data, error } = await sb.from('wp_main_items').insert(payload).select().single();
  if (error) return res.status(500).json({ message: error.message });
  try { await saveVisibilityTargets(sb, 'main', data.id, visibility_targets); }
  catch (e) { return res.status(500).json({ message: e.message }); }
  res.json(data);
});

app.put('/api/wp-main-items/:id', requireAuth, async (req, res) => {
  const sb = requireSupabase(res); if (!sb) return;
  const { data: existing } = await sb.from('wp_main_items').select('id').eq('id', req.params.id).eq('company_id', req.session.companyId).maybeSingle();
  if (!existing) return res.status(404).json({ message: 'الورقة غير موجودة' });
  const { visibility_targets, group_id, company_id, id, ...rest } = req.body;
  const { data, error } = await sb.from('wp_main_items').update(rest).eq('id', req.params.id).select().single();
  if (error) return res.status(500).json({ message: error.message });
  try { await saveVisibilityTargets(sb, 'main', req.params.id, visibility_targets); }
  catch (e) { return res.status(500).json({ message: e.message }); }
  res.json(data);
});

app.delete('/api/wp-main-items/:id', requireAuth, async (req, res) => {
  const sb = requireSupabase(res); if (!sb) return;
  const { data: existing } = await sb.from('wp_main_items').select('id').eq('id', req.params.id).eq('company_id', req.session.companyId).maybeSingle();
  if (!existing) return res.status(404).json({ message: 'الورقة غير موجودة' });
  const { error } = await sb.from('wp_main_items').delete().eq('id', req.params.id);
  if (error) return res.status(500).json({ message: 'تعذّر حذف الورقة (تأكد من عدم وجود بنود فرعية تابعة لها): ' + error.message });
  await sb.from('wp_visibility_targets').delete().eq('entity_type', 'main').eq('entity_id', req.params.id);
  res.json({ ok: true });
});

app.get('/api/wp-sub-items/:id', requireAuth, async (req, res) => {
  const sb = requireSupabase(res); if (!sb) return;
  const { data: sub, error } = await sb.from('wp_sub_items').select('*')
    .eq('id', req.params.id).eq('company_id', req.session.companyId).maybeSingle();
  if (error) return res.status(500).json({ message: error.message });
  if (!sub) return res.status(404).json({ message: 'البند غير موجود' });
  const { data: targets } = await sb.from('wp_visibility_targets').select('*').eq('entity_type', 'sub').eq('entity_id', req.params.id);
  res.json({ sub, targets: targets || [] });
});

app.post('/api/wp-sub-items', requireAuth, async (req, res) => {
  const sb = requireSupabase(res); if (!sb) return;
  const { data: main } = await sb.from('wp_main_items').select('id')
    .eq('id', req.body.main_item_id).eq('company_id', req.session.companyId).maybeSingle();
  if (!main) return res.status(400).json({ message: 'الورقة الرئيسية غير موجودة أو لا تتبع مكتبك' });
  const { visibility_targets, ...rest } = req.body;
  const payload = { ...rest, company_id: req.session.companyId };
  const { data, error } = await sb.from('wp_sub_items').insert(payload).select().single();
  if (error) return res.status(500).json({ message: error.message });
  try { await saveVisibilityTargets(sb, 'sub', data.id, visibility_targets); }
  catch (e) { return res.status(500).json({ message: e.message }); }
  res.json(data);
});

app.put('/api/wp-sub-items/:id', requireAuth, async (req, res) => {
  const sb = requireSupabase(res); if (!sb) return;
  const { data: existing } = await sb.from('wp_sub_items').select('id').eq('id', req.params.id).eq('company_id', req.session.companyId).maybeSingle();
  if (!existing) return res.status(404).json({ message: 'البند غير موجود' });
  const { visibility_targets, main_item_id, company_id, id, ...rest } = req.body;
  const { data, error } = await sb.from('wp_sub_items').update(rest).eq('id', req.params.id).select().single();
  if (error) return res.status(500).json({ message: error.message });
  try { await saveVisibilityTargets(sb, 'sub', req.params.id, visibility_targets); }
  catch (e) { return res.status(500).json({ message: e.message }); }
  res.json(data);
});

app.delete('/api/wp-sub-items/:id', requireAuth, async (req, res) => {
  const sb = requireSupabase(res); if (!sb) return;
  const { data: existing } = await sb.from('wp_sub_items').select('id').eq('id', req.params.id).eq('company_id', req.session.companyId).maybeSingle();
  if (!existing) return res.status(404).json({ message: 'البند غير موجود' });
  const { error } = await sb.from('wp_sub_items').delete().eq('id', req.params.id);
  if (error) return res.status(500).json({ message: error.message });
  await sb.from('wp_visibility_targets').delete().eq('entity_type', 'sub').eq('entity_id', req.params.id);
  res.json({ ok: true });
});

// ---------------------------------------------------------------------------
// القوائم المرجعية (لتعبئة القوائم المنسدلة بالواجهة)
// ---------------------------------------------------------------------------
app.get('/api/lookups', requireAuth, async (req, res) => {
  const sb = requireSupabase(res); if (!sb) return;
  const companyId = req.session.companyId;
  const [{ data: branches }, { data: clientTypes }, { data: sectors }, { data: regions }, { data: roles }] = await Promise.all([
    sb.from('branches').select('id,name,city,is_main').eq('company_id', companyId).order('name'),
    sb.from('client_types').select('id,name').or(`company_id.eq.${companyId},company_id.is.null`).order('name'),
    sb.from('sectors').select('id,name').or(`company_id.eq.${companyId},company_id.is.null`).order('name'),
    sb.from('regions').select('id,name').or(`company_id.eq.${companyId},company_id.is.null`).order('name'),
    sb.from('roles').select('id,code,name_ar,level').order('level'),
  ]);
  res.json({ branches: branches || [], clientTypes: clientTypes || [], sectors: sectors || [], regions: regions || [], roles: roles || [] });
});

app.post('/api/client-types', requireAuth, async (req, res) => {
  const sb = requireSupabase(res); if (!sb) return;
  const name = (req.body.name || '').trim();
  if (!name) return res.status(400).json({ message: 'الاسم إلزامي' });
  const { data, error } = await sb.from('client_types').insert({ name, company_id: req.session.companyId }).select().single();
  if (error) return res.status(500).json({ message: error.message });
  res.json(data);
});

app.post('/api/sectors', requireAuth, async (req, res) => {
  const sb = requireSupabase(res); if (!sb) return;
  const name = (req.body.name || '').trim();
  if (!name) return res.status(400).json({ message: 'الاسم إلزامي' });
  const { data, error } = await sb.from('sectors').insert({ name, company_id: req.session.companyId }).select().single();
  if (error) return res.status(500).json({ message: error.message });
  res.json(data);
});

app.post('/api/regions', requireAuth, async (req, res) => {
  const sb = requireSupabase(res); if (!sb) return;
  const name = (req.body.name || '').trim();
  if (!name) return res.status(400).json({ message: 'الاسم إلزامي' });
  const { data, error } = await sb.from('regions').insert({ name, company_id: req.session.companyId }).select().single();
  if (error) return res.status(500).json({ message: error.message });
  res.json(data);
});

// ---------------------------------------------------------------------------
// العملاء
// ---------------------------------------------------------------------------
app.get('/api/clients', requireAuth, async (req, res) => {
  const sb = requireSupabase(res); if (!sb) return;
  const { data, error } = await sb.from('clients')
    .select('id,name,client_code,status,client_type_id,sector_id,region_id,review_manager_id,created_at')
    .eq('company_id', req.session.companyId)
    .order('created_at', { ascending: false });
  if (error) return res.status(500).json({ message: error.message });
  res.json(data);
});

app.post('/api/clients', requireAuth, async (req, res) => {
  const sb = requireSupabase(res); if (!sb) return;
  const payload = { ...req.body, company_id: req.session.companyId, created_by: req.session.userId };
  const { data, error } = await sb.from('clients').insert(payload).select().single();
  if (error) return res.status(500).json({ message: error.message });
  res.json(data);
});

app.get('/api/clients/:id', requireAuth, async (req, res) => {
  const sb = requireSupabase(res); if (!sb) return;
  const { data: client, error } = await sb.from('clients').select('*')
    .eq('id', req.params.id).eq('company_id', req.session.companyId).maybeSingle();
  if (error) return res.status(500).json({ message: error.message });
  if (!client) return res.status(404).json({ message: 'العميل غير موجود' });
  const { data: employees, error: empErr } = await sb.from('client_employees').select('*').eq('client_id', client.id).order('created_at');
  if (empErr) return res.status(500).json({ message: empErr.message });
  const { data: files, error: filesErr } = await sb.from('client_files').select('id,name,period_end,engagement_type,status,created_at').eq('client_id', client.id).order('created_at', { ascending: false });
  if (filesErr) return res.status(500).json({ message: filesErr.message });
  res.json({ client, employees: employees || [], files: files || [] });
});

app.put('/api/clients/:id', requireAuth, async (req, res) => {
  const sb = requireSupabase(res); if (!sb) return;
  const { data: existing } = await sb.from('clients').select('id').eq('id', req.params.id).eq('company_id', req.session.companyId).maybeSingle();
  if (!existing) return res.status(404).json({ message: 'العميل غير موجود' });
  const { data, error } = await sb.from('clients').update(req.body).eq('id', req.params.id).select().single();
  if (error) return res.status(500).json({ message: error.message });
  res.json(data);
});

app.delete('/api/clients/:id', requireAuth, async (req, res) => {
  const sb = requireSupabase(res); if (!sb) return;
  const { data: existing } = await sb.from('clients').select('id').eq('id', req.params.id).eq('company_id', req.session.companyId).maybeSingle();
  if (!existing) return res.status(404).json({ message: 'العميل غير موجود' });
  const { error } = await sb.from('clients').delete().eq('id', req.params.id);
  if (error) return res.status(500).json({ message: 'تعذّر حذف العميل: ' + error.message });
  res.json({ ok: true });
});

app.post('/api/clients/:id/employees', requireAuth, async (req, res) => {
  const sb = requireSupabase(res); if (!sb) return;
  const { data: client } = await sb.from('clients').select('id').eq('id', req.params.id).eq('company_id', req.session.companyId).maybeSingle();
  if (!client) return res.status(404).json({ message: 'العميل غير موجود' });
  const { data, error } = await sb.from('client_employees').insert({ ...req.body, client_id: req.params.id }).select().single();
  if (error) return res.status(500).json({ message: error.message });
  res.json(data);
});

app.put('/api/clients/:id/employees/:empId', requireAuth, async (req, res) => {
  const sb = requireSupabase(res); if (!sb) return;
  const { data: client } = await sb.from('clients').select('id').eq('id', req.params.id).eq('company_id', req.session.companyId).maybeSingle();
  if (!client) return res.status(404).json({ message: 'العميل غير موجود' });
  const body = req.body || {};
  const payload = {
    full_name: body.full_name, job_title: body.job_title || null,
    email: body.email || null, phone: body.phone || null,
    is_primary_contact: !!body.is_primary_contact,
  };
  const { data, error } = await sb.from('client_employees').update(payload)
    .eq('id', req.params.empId).eq('client_id', req.params.id).select().single();
  if (error) return res.status(500).json({ message: error.message });
  res.json(data);
});

app.delete('/api/clients/:id/employees/:empId', requireAuth, async (req, res) => {
  const sb = requireSupabase(res); if (!sb) return;
  const { data: client } = await sb.from('clients').select('id').eq('id', req.params.id).eq('company_id', req.session.companyId).maybeSingle();
  if (!client) return res.status(404).json({ message: 'العميل غير موجود' });
  const { error } = await sb.from('client_employees').delete().eq('id', req.params.empId).eq('client_id', req.params.id);
  if (error) return res.status(500).json({ message: error.message });
  res.json({ ok: true });
});

// ---------------------------------------------------------------------------
// ملفات التدقيق (Engagement files)
// ---------------------------------------------------------------------------
app.get('/api/client-files', requireAuth, async (req, res) => {
  const sb = requireSupabase(res); if (!sb) return;
  let query = sb.from('client_files')
    .select('id,name,period_end,engagement_type,status,created_at,client_id,clients!inner(id,name,company_id)')
    .eq('clients.company_id', req.session.companyId)
    .order('created_at', { ascending: false });
  if (req.query.clientId) query = query.eq('client_id', req.query.clientId);
  const { data, error } = await query;
  if (error) return res.status(500).json({ message: error.message });
  res.json(data);
});

app.post('/api/clients/:id/files', requireAuth, async (req, res) => {
  const sb = requireSupabase(res); if (!sb) return;
  const { data: client } = await sb.from('clients').select('id').eq('id', req.params.id).eq('company_id', req.session.companyId).maybeSingle();
  if (!client) return res.status(404).json({ message: 'العميل غير موجود' });
  const payload = { ...req.body, client_id: req.params.id, created_by: req.session.userId };
  const { data, error } = await sb.from('client_files').insert(payload).select().single();
  if (error) return res.status(500).json({ message: error.message });
  res.json(data);
});

async function assertFileInCompany(sb, fileId, companyId) {
  const { data, error } = await sb.from('client_files')
    .select('id, client_id, name, period_start, period_end, prev_period_start, prev_period_end, engagement_type, status, clients!inner(id,name,company_id)')
    .eq('id', fileId).eq('clients.company_id', companyId).maybeSingle();
  if (error) console.error('assertFileInCompany query error:', error.message);
  return data;
}

app.get('/api/client-files/:id', requireAuth, async (req, res) => {
  const sb = requireSupabase(res); if (!sb) return;
  const file = await assertFileInCompany(sb, req.params.id, req.session.companyId);
  if (!file) return res.status(404).json({ message: 'الملف غير موجود' });
  res.json(file);
});

app.put('/api/client-files/:id', requireAuth, async (req, res) => {
  const sb = requireSupabase(res); if (!sb) return;
  const file = await assertFileInCompany(sb, req.params.id, req.session.companyId);
  if (!file) return res.status(404).json({ message: 'الملف غير موجود' });
  const body = req.body || {};
  const payload = {};
  if (body.name !== undefined) payload.name = body.name;
  if (body.period_start !== undefined) payload.period_start = body.period_start || null;
  if (body.period_end !== undefined) payload.period_end = body.period_end || null;
  if (body.prev_period_start !== undefined) payload.prev_period_start = body.prev_period_start || null;
  if (body.prev_period_end !== undefined) payload.prev_period_end = body.prev_period_end || null;
  if (body.engagement_type !== undefined) payload.engagement_type = body.engagement_type || null;
  if (body.status !== undefined) payload.status = body.status;
  const { data, error } = await sb.from('client_files').update(payload).eq('id', req.params.id).select().single();
  if (error) return res.status(500).json({ message: error.message });
  res.json(data);
});

app.delete('/api/client-files/:id', requireAuth, async (req, res) => {
  const sb = requireSupabase(res); if (!sb) return;
  const file = await assertFileInCompany(sb, req.params.id, req.session.companyId);
  if (!file) return res.status(404).json({ message: 'الملف غير موجود' });
  const { error } = await sb.from('client_files').delete().eq('id', req.params.id);
  if (error) return res.status(500).json({ message: 'تعذّر حذف الملف: ' + error.message });
  res.json({ ok: true });
});

// ---------------------------------------------------------------------------
// فريق المراجعة الخاص بملف تدقيق محدد (عدة مراجعين، واحد منهم مسؤول الملف)
// ---------------------------------------------------------------------------
app.get('/api/client-files/:id/team', requireAuth, async (req, res) => {
  const sb = requireSupabase(res); if (!sb) return;
  const file = await assertFileInCompany(sb, req.params.id, req.session.companyId);
  if (!file) return res.status(404).json({ message: 'الملف غير موجود' });
  const { data, error } = await sb.from('client_file_team')
    .select('id, user_id, is_lead, assigned_at, users(id, first_name_ar, last_name_ar, roles(name_ar))')
    .eq('client_file_id', req.params.id).order('is_lead', { ascending: false });
  if (error) return res.status(500).json({ message: error.message });
  res.json(data || []);
});

app.post('/api/client-files/:id/team', requireAuth, async (req, res) => {
  const sb = requireSupabase(res); if (!sb) return;
  const file = await assertFileInCompany(sb, req.params.id, req.session.companyId);
  if (!file) return res.status(404).json({ message: 'الملف غير موجود' });
  const { data: user } = await sb.from('users').select('id').eq('id', req.body.user_id).eq('company_id', req.session.companyId).maybeSingle();
  if (!user) return res.status(400).json({ message: 'المستخدم غير موجود ضمن مكتبك' });
  const makeLead = !!req.body.is_lead;
  if (makeLead) {
    // مسؤول واحد فقط لكل ملف — نلغي القيادة عن أي عضو سابق قبل تعيين الجديد
    await sb.from('client_file_team').update({ is_lead: false }).eq('client_file_id', req.params.id);
  }
  const { data, error } = await sb.from('client_file_team')
    .upsert({ client_file_id: req.params.id, user_id: req.body.user_id, is_lead: makeLead }, { onConflict: 'client_file_id,user_id' })
    .select().single();
  if (error) return res.status(500).json({ message: error.message });
  res.json(data);
});

app.put('/api/client-files/:id/team/:userId', requireAuth, async (req, res) => {
  const sb = requireSupabase(res); if (!sb) return;
  const file = await assertFileInCompany(sb, req.params.id, req.session.companyId);
  if (!file) return res.status(404).json({ message: 'الملف غير موجود' });
  if (req.body.is_lead) {
    await sb.from('client_file_team').update({ is_lead: false }).eq('client_file_id', req.params.id);
  }
  const { data, error } = await sb.from('client_file_team')
    .update({ is_lead: !!req.body.is_lead }).eq('client_file_id', req.params.id).eq('user_id', req.params.userId).select().single();
  if (error) return res.status(500).json({ message: error.message });
  res.json(data);
});

app.delete('/api/client-files/:id/team/:userId', requireAuth, async (req, res) => {
  const sb = requireSupabase(res); if (!sb) return;
  const file = await assertFileInCompany(sb, req.params.id, req.session.companyId);
  if (!file) return res.status(404).json({ message: 'الملف غير موجود' });
  const { error } = await sb.from('client_file_team').delete().eq('client_file_id', req.params.id).eq('user_id', req.params.userId);
  if (error) return res.status(500).json({ message: error.message });
  res.json({ ok: true });
});

// ---------------------------------------------------------------------------
// ميزان المراجعة (تهيئة الميزان)
// ---------------------------------------------------------------------------
app.get('/api/client-files/:id/trial-balance', requireAuth, async (req, res) => {
  const sb = requireSupabase(res); if (!sb) return;
  const file = await assertFileInCompany(sb, req.params.id, req.session.companyId);
  if (!file) return res.status(404).json({ message: 'الملف غير موجود' });
  const { data: latest } = await sb.from('trial_balances').select('*').eq('client_file_id', req.params.id).order('version', { ascending: false }).limit(1).maybeSingle();
  const { data: adjustments } = await sb.from('trial_balance_adjustments').select('*').eq('client_file_id', req.params.id).order('created_at');
  if (!latest) return res.json({ trialBalance: null, lines: [], adjustments: adjustments || [] });
  const { data: lines, error } = await sb.from('trial_balance_lines').select('*').eq('trial_balance_id', latest.id).order('account_code');
  if (error) return res.status(500).json({ message: error.message });
  res.json({ trialBalance: latest, lines, adjustments: adjustments || [] });
});

// ---------------------------------------------------------------------------
// قيود التعديل (Adjusting Journal Entries) — تنعكس على "الميزان المعدَّل" فورًا
// ---------------------------------------------------------------------------
app.get('/api/client-files/:id/adjustments', requireAuth, async (req, res) => {
  const sb = requireSupabase(res); if (!sb) return;
  const file = await assertFileInCompany(sb, req.params.id, req.session.companyId);
  if (!file) return res.status(404).json({ message: 'الملف غير موجود' });
  const { data, error } = await sb.from('trial_balance_adjustments').select('*').eq('client_file_id', req.params.id).order('created_at');
  if (error) return res.status(500).json({ message: error.message });
  res.json(data || []);
});

app.post('/api/client-files/:id/adjustments', requireAuth, async (req, res) => {
  const sb = requireSupabase(res); if (!sb) return;
  const file = await assertFileInCompany(sb, req.params.id, req.session.companyId);
  if (!file) return res.status(404).json({ message: 'الملف غير موجود' });
  const b = req.body || {};
  if (!b.debit_account_code || !b.credit_account_code) return res.status(400).json({ message: 'اختر الحساب المدين والحساب الدائن' });
  const payload = {
    client_file_id: req.params.id,
    debit_account_code: b.debit_account_code,
    debit_account_name: b.debit_account_name || null,
    credit_account_code: b.credit_account_code,
    credit_account_name: b.credit_account_name || null,
    amount: Number(b.amount) || 0,
    affects: b.affects === 'opening' ? 'opening' : 'closing',
    narration: b.narration || null,
    created_by: req.session.userId,
  };
  const { data, error } = await sb.from('trial_balance_adjustments').insert(payload).select().single();
  if (error) return res.status(500).json({ message: error.message });
  res.json(data);
});

app.put('/api/client-files/:id/adjustments/:adjId', requireAuth, async (req, res) => {
  const sb = requireSupabase(res); if (!sb) return;
  const file = await assertFileInCompany(sb, req.params.id, req.session.companyId);
  if (!file) return res.status(404).json({ message: 'الملف غير موجود' });
  const b = req.body || {};
  if (!b.debit_account_code || !b.credit_account_code) return res.status(400).json({ message: 'اختر الحساب المدين والحساب الدائن' });
  const payload = {
    debit_account_code: b.debit_account_code,
    debit_account_name: b.debit_account_name || null,
    credit_account_code: b.credit_account_code,
    credit_account_name: b.credit_account_name || null,
    amount: Number(b.amount) || 0,
    affects: b.affects === 'opening' ? 'opening' : 'closing',
    narration: b.narration || null,
  };
  const { data, error } = await sb.from('trial_balance_adjustments').update(payload)
    .eq('id', req.params.adjId).eq('client_file_id', req.params.id).select().single();
  if (error) return res.status(500).json({ message: error.message });
  res.json(data);
});

app.delete('/api/client-files/:id/adjustments/:adjId', requireAuth, async (req, res) => {
  const sb = requireSupabase(res); if (!sb) return;
  const file = await assertFileInCompany(sb, req.params.id, req.session.companyId);
  if (!file) return res.status(404).json({ message: 'الملف غير موجود' });
  const { error } = await sb.from('trial_balance_adjustments').delete().eq('id', req.params.adjId).eq('client_file_id', req.params.id);
  if (error) return res.status(500).json({ message: error.message });
  res.json({ ok: true });
});

// ---------------------------------------------------------------------------
// نظام الدردشة — دردشة عميل واحدة (تُرى من كل فريق المراجعة)، تُصفَّى حسب الملف
// أو بند العمل عند التصفح من داخلهما، وتُجمع بالكامل عند عرض "دردشة العميل"
// ---------------------------------------------------------------------------
app.get('/api/client-files/:id/chat', requireAuth, async (req, res) => {
  const sb = requireSupabase(res); if (!sb) return;
  const file = await assertFileInCompany(sb, req.params.id, req.session.companyId);
  if (!file) return res.status(404).json({ message: 'الملف غير موجود' });
  let q = sb.from('chat_messages')
    .select('id, body, attachment_name, attachment_mime, attachment_data, created_at, wp_main_item_id, client_file_id, sender_user_id, users(id, first_name_ar, last_name_ar, roles(name_ar)), wp_main_items(title)')
    .eq('client_file_id', req.params.id).order('created_at');
  // بدون تحديد بند: تُعرض كل رسائل الملف (العامة وأي رسالة مرتبطة ببند). بتحديد بند: تُصفَّى لرسائله فقط.
  if (req.query.mainItemId) q = q.eq('wp_main_item_id', req.query.mainItemId);
  const { data, error } = await q;
  if (error) return res.status(500).json({ message: error.message });
  res.json(data || []);
});

app.post('/api/client-files/:id/chat', requireAuth, async (req, res) => {
  const sb = requireSupabase(res); if (!sb) return;
  const file = await assertFileInCompany(sb, req.params.id, req.session.companyId);
  if (!file) return res.status(404).json({ message: 'الملف غير موجود' });
  const b = req.body || {};
  if (!b.body && !b.attachment_data) return res.status(400).json({ message: 'الرسالة فارغة' });
  const payload = {
    company_id: req.session.companyId,
    client_id: file.client_id,
    client_file_id: req.params.id,
    wp_main_item_id: b.wp_main_item_id || null,
    sender_user_id: req.session.userId,
    body: b.body || null,
    attachment_name: b.attachment_name || null,
    attachment_mime: b.attachment_mime || null,
    attachment_data: b.attachment_data || null,
  };
  const { data, error } = await sb.from('chat_messages').insert(payload)
    .select('id, body, attachment_name, attachment_mime, attachment_data, created_at, wp_main_item_id, client_file_id, sender_user_id, users(id, first_name_ar, last_name_ar, roles(name_ar)), wp_main_items(title)')
    .single();
  if (error) return res.status(500).json({ message: error.message });
  res.json(data);
});

app.get('/api/client-files/:id/client-employees', requireAuth, async (req, res) => {
  const sb = requireSupabase(res); if (!sb) return;
  const file = await assertFileInCompany(sb, req.params.id, req.session.companyId);
  if (!file) return res.status(404).json({ message: 'الملف غير موجود' });
  const { data, error } = await sb.from('client_employees').select('id, full_name, job_title, email').eq('client_id', file.client_id).order('full_name');
  if (error) return res.status(500).json({ message: error.message });
  res.json(data || []);
});

// ---------------------------------------------------------------------------
// تعديل رسالة دردشة موجودة (ربطها ببند عمل رئيسي بأثر رجعي)
// ---------------------------------------------------------------------------
app.put('/api/client-files/:id/chat/:msgId', requireAuth, async (req, res) => {
  const sb = requireSupabase(res); if (!sb) return;
  const file = await assertFileInCompany(sb, req.params.id, req.session.companyId);
  if (!file) return res.status(404).json({ message: 'الملف غير موجود' });
  const { data, error } = await sb.from('chat_messages')
    .update({ wp_main_item_id: req.body.wp_main_item_id || null })
    .eq('id', req.params.msgId).eq('client_file_id', req.params.id)
    .select('id, wp_main_item_id').single();
  if (error) return res.status(500).json({ message: error.message });
  res.json(data);
});

// ---------------------------------------------------------------------------
// المتطلبات — طلب مرفق من العميل عبر الدردشة، ومتابعة نسبة الاستيفاء
// ---------------------------------------------------------------------------
app.get('/api/client-files/:id/requirements', requireAuth, async (req, res) => {
  const sb = requireSupabase(res); if (!sb) return;
  const file = await assertFileInCompany(sb, req.params.id, req.session.companyId);
  if (!file) return res.status(404).json({ message: 'الملف غير موجود' });
  const { data, error } = await sb.from('wp_requirements')
    .select('*, wp_main_items(title), users(first_name_ar, last_name_ar)')
    .eq('client_file_id', req.params.id).order('created_at', { ascending: false });
  if (error) return res.status(500).json({ message: error.message });
  res.json(data || []);
});

app.post('/api/client-files/:id/requirements', requireAuth, async (req, res) => {
  const sb = requireSupabase(res); if (!sb) return;
  const file = await assertFileInCompany(sb, req.params.id, req.session.companyId);
  if (!file) return res.status(404).json({ message: 'الملف غير موجود' });
  const b = req.body || {};
  if (!b.title || !b.title.trim()) return res.status(400).json({ message: 'اسم المتطلب إلزامي' });
  const payload = {
    client_file_id: req.params.id,
    wp_main_item_id: b.wp_main_item_id || null,
    title: b.title.trim(),
    created_by: req.session.userId,
  };
  const { data: req_, error } = await sb.from('wp_requirements').insert(payload).select().single();
  if (error) return res.status(500).json({ message: error.message });

  // إرسال رسالة دردشة مرتبطة بهذا المتطلب تلقائيًا
  const { data: msg } = await sb.from('chat_messages').insert({
    company_id: req.session.companyId, client_id: file.client_id, client_file_id: req.params.id,
    wp_main_item_id: b.wp_main_item_id || null, sender_user_id: req.session.userId,
    body: '📋 طلب مرفق: ' + req_.title, requirement_id: req_.id,
  }).select('id').single();
  if (msg) await sb.from('wp_requirements').update({ chat_message_id: msg.id }).eq('id', req_.id);

  res.json(req_);
});

app.post('/api/client-files/:id/requirements/:reqId/fulfill', requireAuth, async (req, res) => {
  const sb = requireSupabase(res); if (!sb) return;
  const file = await assertFileInCompany(sb, req.params.id, req.session.companyId);
  if (!file) return res.status(404).json({ message: 'الملف غير موجود' });
  const b = req.body || {};
  const payload = {
    is_fulfilled: true,
    fulfilled_attachment_name: b.attachment_name || null,
    fulfilled_attachment_mime: b.attachment_mime || null,
    fulfilled_attachment_data: b.attachment_data || null,
    fulfilled_at: new Date().toISOString(),
  };
  const { data, error } = await sb.from('wp_requirements').update(payload)
    .eq('id', req.params.reqId).eq('client_file_id', req.params.id).select().single();
  if (error) return res.status(500).json({ message: error.message });
  res.json(data);
});

app.delete('/api/client-files/:id/requirements/:reqId', requireAuth, async (req, res) => {
  const sb = requireSupabase(res); if (!sb) return;
  const file = await assertFileInCompany(sb, req.params.id, req.session.companyId);
  if (!file) return res.status(404).json({ message: 'الملف غير موجود' });
  const { error } = await sb.from('wp_requirements').delete().eq('id', req.params.reqId).eq('client_file_id', req.params.id);
  if (error) return res.status(500).json({ message: error.message });
  res.json({ ok: true });
});

// ---------------------------------------------------------------------------
// الملاحظات — تعمل بنفس آلية المتطلبات (تبدأ بـ ! بالدردشة) لكن حالتها محلولة/غير محلولة
// ---------------------------------------------------------------------------
app.get('/api/client-files/:id/notes', requireAuth, async (req, res) => {
  const sb = requireSupabase(res); if (!sb) return;
  const file = await assertFileInCompany(sb, req.params.id, req.session.companyId);
  if (!file) return res.status(404).json({ message: 'الملف غير موجود' });
  const { data, error } = await sb.from('wp_notes')
    .select('*, wp_main_items(title), created:users!wp_notes_created_by_fkey(first_name_ar, last_name_ar)')
    .eq('client_file_id', req.params.id).order('created_at', { ascending: false });
  if (error) return res.status(500).json({ message: error.message });
  res.json(data || []);
});

app.post('/api/client-files/:id/notes', requireAuth, async (req, res) => {
  const sb = requireSupabase(res); if (!sb) return;
  const file = await assertFileInCompany(sb, req.params.id, req.session.companyId);
  if (!file) return res.status(404).json({ message: 'الملف غير موجود' });
  const b = req.body || {};
  if (!b.body || !b.body.trim()) return res.status(400).json({ message: 'نص الملاحظة إلزامي' });
  const payload = { client_file_id: req.params.id, wp_main_item_id: b.wp_main_item_id || null, body: b.body.trim(), created_by: req.session.userId };
  const { data: note, error } = await sb.from('wp_notes').insert(payload).select().single();
  if (error) return res.status(500).json({ message: error.message });

  const { data: msg } = await sb.from('chat_messages').insert({
    company_id: req.session.companyId, client_id: file.client_id, client_file_id: req.params.id,
    wp_main_item_id: b.wp_main_item_id || null, sender_user_id: req.session.userId,
    body: '📝 ملاحظة: ' + note.body, note_id: note.id,
  }).select('id').single();
  if (msg) await sb.from('wp_notes').update({ chat_message_id: msg.id }).eq('id', note.id);

  res.json(note);
});

app.post('/api/client-files/:id/notes/:noteId/resolve', requireAuth, async (req, res) => {
  const sb = requireSupabase(res); if (!sb) return;
  const file = await assertFileInCompany(sb, req.params.id, req.session.companyId);
  if (!file) return res.status(404).json({ message: 'الملف غير موجود' });
  const { data, error } = await sb.from('wp_notes')
    .update({ is_resolved: !!req.body.is_resolved, resolved_by: req.session.userId, resolved_at: new Date().toISOString() })
    .eq('id', req.params.noteId).eq('client_file_id', req.params.id).select().single();
  if (error) return res.status(500).json({ message: error.message });
  res.json(data);
});

app.delete('/api/client-files/:id/notes/:noteId', requireAuth, async (req, res) => {
  const sb = requireSupabase(res); if (!sb) return;
  const file = await assertFileInCompany(sb, req.params.id, req.session.companyId);
  if (!file) return res.status(404).json({ message: 'الملف غير موجود' });
  const { error } = await sb.from('wp_notes').delete().eq('id', req.params.noteId).eq('client_file_id', req.params.id);
  if (error) return res.status(500).json({ message: error.message });
  res.json({ ok: true });
});

// ---------------------------------------------------------------------------
// المرفقات — تجميع كل مرفق بالملف من أي مصدر (متطلبات، أوراق عمل، دردشات) بمكان واحد
// ---------------------------------------------------------------------------
app.get('/api/client-files/:id/attachments', requireAuth, async (req, res) => {
  const sb = requireSupabase(res); if (!sb) return;
  const file = await assertFileInCompany(sb, req.params.id, req.session.companyId);
  if (!file) return res.status(404).json({ message: 'الملف غير موجود' });

  const results = [];

  const { data: chatFiles } = await sb.from('chat_messages')
    .select('id, attachment_name, attachment_mime, attachment_data, created_at, wp_main_item_id, users(first_name_ar, last_name_ar), wp_main_items(title)')
    .eq('client_file_id', req.params.id).not('attachment_data', 'is', null);
  (chatFiles || []).forEach(m => results.push({
    source: 'chat', name: m.attachment_name, mime: m.attachment_mime, data: m.attachment_data, created_at: m.created_at,
    context: m.wp_main_items ? 'دردشة — ' + m.wp_main_items.title : 'دردشة الملف العامة',
    by: m.users ? ((m.users.first_name_ar || '') + ' ' + (m.users.last_name_ar || '')).trim() : null,
  }));

  const { data: reqFiles } = await sb.from('wp_requirements')
    .select('id, title, fulfilled_attachment_name, fulfilled_attachment_mime, fulfilled_attachment_data, fulfilled_at, wp_main_items(title)')
    .eq('client_file_id', req.params.id).eq('is_fulfilled', true);
  (reqFiles || []).forEach(r => results.push({
    source: 'requirement', name: r.fulfilled_attachment_name, mime: r.fulfilled_attachment_mime, data: r.fulfilled_attachment_data, created_at: r.fulfilled_at,
    context: 'متطلب: ' + r.title + (r.wp_main_items ? ' — ' + r.wp_main_items.title : ''), by: null,
  }));

  const { data: subs } = await sb.from('wp_sub_items').select('id, label, main_item_id, wp_main_items(title)');
  const subsById = {}; (subs || []).forEach(s => subsById[s.id] = s);
  const { data: wpFiles } = await sb.from('client_file_wp_answers')
    .select('wp_sub_item_id, attachment_url, answered_at, users:answered_by(first_name_ar, last_name_ar)')
    .eq('client_file_id', req.params.id).not('attachment_url', 'is', null);
  (wpFiles || []).forEach(a => {
    const s = subsById[a.wp_sub_item_id];
    results.push({
      source: 'workpaper', name: (s ? s.label : 'مرفق') + '.file', mime: null, data: a.attachment_url, created_at: a.answered_at,
      context: s ? ('ورقة عمل — ' + (s.wp_main_items ? s.wp_main_items.title + ' — ' : '') + s.label) : 'ورقة عمل',
      by: a.users ? ((a.users.first_name_ar || '') + ' ' + (a.users.last_name_ar || '')).trim() : null,
    });
  });

  results.sort((a, b) => new Date(b.created_at || 0) - new Date(a.created_at || 0));
  res.json(results);
});

// دردشة العميل المجمّعة — كل الرسائل بكل ملفاته التدقيقية بمكان واحد (مثل واتساب)
app.get('/api/clients/:id/chat', requireAuth, async (req, res) => {
  const sb = requireSupabase(res); if (!sb) return;
  const { data: client } = await sb.from('clients').select('id').eq('id', req.params.id).eq('company_id', req.session.companyId).maybeSingle();
  if (!client) return res.status(404).json({ message: 'العميل غير موجود' });
  const { data, error } = await sb.from('chat_messages')
    .select('id, body, attachment_name, attachment_mime, attachment_data, created_at, wp_main_item_id, client_file_id, sender_user_id, users(id, first_name_ar, last_name_ar, roles(name_ar)), wp_main_items(title), client_files(name)')
    .eq('client_id', req.params.id).order('created_at');
  if (error) return res.status(500).json({ message: error.message });
  res.json(data || []);
});

// ---------------------------------------------------------------------------
// دردشات فريق المكتب: مجموعة عامة لكل الموظفين + رسائل خاصة بين اثنين فقط
// ---------------------------------------------------------------------------
app.get('/api/staff-chat/group', requireAuth, async (req, res) => {
  const sb = requireSupabase(res); if (!sb) return;
  const { data, error } = await sb.from('staff_messages')
    .select('id, body, attachment_name, attachment_mime, attachment_data, created_at, sender_user_id, users(id, first_name_ar, last_name_ar, roles(name_ar))')
    .eq('company_id', req.session.companyId).is('recipient_user_id', null).is('group_id', null).order('created_at');
  if (error) return res.status(500).json({ message: error.message });
  res.json(data || []);
});

app.post('/api/staff-chat/group', requireAuth, async (req, res) => {
  const sb = requireSupabase(res); if (!sb) return;
  const b = req.body || {};
  if (!b.body && !b.attachment_data) return res.status(400).json({ message: 'الرسالة فارغة' });
  const payload = {
    company_id: req.session.companyId, sender_user_id: req.session.userId, recipient_user_id: null,
    body: b.body || null, attachment_name: b.attachment_name || null, attachment_mime: b.attachment_mime || null, attachment_data: b.attachment_data || null,
  };
  const { data, error } = await sb.from('staff_messages').insert(payload)
    .select('id, body, attachment_name, attachment_mime, attachment_data, created_at, sender_user_id, users(id, first_name_ar, last_name_ar, roles(name_ar))').single();
  if (error) return res.status(500).json({ message: error.message });
  res.json(data);
});

// ---------------------------------------------------------------------------
// مجموعات دردشة مخصّصة بين عدة موظفين (أكثر من شخصين)
// ---------------------------------------------------------------------------
app.get('/api/staff-chat/groups', requireAuth, async (req, res) => {
  const sb = requireSupabase(res); if (!sb) return;
  const { data: myMemberships } = await sb.from('staff_chat_group_members').select('group_id').eq('user_id', req.session.userId);
  const groupIds = (myMemberships || []).map(m => m.group_id);
  if (!groupIds.length) return res.json([]);
  const { data: groups, error } = await sb.from('staff_chat_groups').select('*, staff_chat_group_members(user_id, users(first_name_ar, last_name_ar))').in('id', groupIds);
  if (error) return res.status(500).json({ message: error.message });
  const { data: lastMsgs } = await sb.from('staff_messages').select('group_id, body, created_at').in('group_id', groupIds).order('created_at', { ascending: false });
  const lastByGroup = {}; (lastMsgs || []).forEach(m => { if (!lastByGroup[m.group_id]) lastByGroup[m.group_id] = m; });
  const result = (groups || []).map(g => ({
    id: g.id, name: g.name,
    members: (g.staff_chat_group_members || []).map(m => ((m.users.first_name_ar || '') + ' ' + (m.users.last_name_ar || '')).trim()),
    last_message: lastByGroup[g.id] ? lastByGroup[g.id].body : null,
    last_message_at: lastByGroup[g.id] ? lastByGroup[g.id].created_at : null,
  })).sort((a, b) => new Date(b.last_message_at || 0) - new Date(a.last_message_at || 0));
  res.json(result);
});

app.post('/api/staff-chat/groups', requireAuth, async (req, res) => {
  const sb = requireSupabase(res); if (!sb) return;
  const b = req.body || {};
  if (!b.name || !b.name.trim()) return res.status(400).json({ message: 'اسم المجموعة إلزامي' });
  const memberIds = Array.isArray(b.member_ids) ? b.member_ids.filter(id => id !== req.session.userId) : [];
  if (!memberIds.length) return res.status(400).json({ message: 'اختر عضوًا واحدًا على الأقل' });
  const { data: group, error } = await sb.from('staff_chat_groups').insert({ company_id: req.session.companyId, name: b.name.trim(), created_by: req.session.userId }).select().single();
  if (error) return res.status(500).json({ message: error.message });
  const allMembers = [...new Set([req.session.userId, ...memberIds])].map(uid => ({ group_id: group.id, user_id: uid }));
  const { error: memErr } = await sb.from('staff_chat_group_members').insert(allMembers);
  if (memErr) return res.status(500).json({ message: memErr.message });
  res.json(group);
});

app.get('/api/staff-chat/groups/:groupId/messages', requireAuth, async (req, res) => {
  const sb = requireSupabase(res); if (!sb) return;
  const { data: member } = await sb.from('staff_chat_group_members').select('id').eq('group_id', req.params.groupId).eq('user_id', req.session.userId).maybeSingle();
  if (!member) return res.status(403).json({ message: 'لست عضوًا بهذه المجموعة' });
  const { data, error } = await sb.from('staff_messages')
    .select('id, body, attachment_name, attachment_mime, attachment_data, created_at, sender_user_id, users(id, first_name_ar, last_name_ar, roles(name_ar))')
    .eq('group_id', req.params.groupId).order('created_at');
  if (error) return res.status(500).json({ message: error.message });
  res.json(data || []);
});

app.post('/api/staff-chat/groups/:groupId/messages', requireAuth, async (req, res) => {
  const sb = requireSupabase(res); if (!sb) return;
  const { data: member } = await sb.from('staff_chat_group_members').select('id').eq('group_id', req.params.groupId).eq('user_id', req.session.userId).maybeSingle();
  if (!member) return res.status(403).json({ message: 'لست عضوًا بهذه المجموعة' });
  const b = req.body || {};
  if (!b.body && !b.attachment_data) return res.status(400).json({ message: 'الرسالة فارغة' });
  const payload = {
    company_id: req.session.companyId, sender_user_id: req.session.userId, group_id: req.params.groupId,
    body: b.body || null, attachment_name: b.attachment_name || null, attachment_mime: b.attachment_mime || null, attachment_data: b.attachment_data || null,
  };
  const { data, error } = await sb.from('staff_messages').insert(payload)
    .select('id, body, attachment_name, attachment_mime, attachment_data, created_at, sender_user_id, users(id, first_name_ar, last_name_ar, roles(name_ar))').single();
  if (error) return res.status(500).json({ message: error.message });
  res.json(data);
});

app.get('/api/staff-chat/dm/:userId', requireAuth, async (req, res) => {
  const sb = requireSupabase(res); if (!sb) return;
  const { data: peer } = await sb.from('users').select('id').eq('id', req.params.userId).eq('company_id', req.session.companyId).maybeSingle();
  if (!peer) return res.status(404).json({ message: 'المستخدم غير موجود' });
  const me = req.session.userId;
  const { data, error } = await sb.from('staff_messages')
    .select('id, body, attachment_name, attachment_mime, attachment_data, created_at, sender_user_id, recipient_user_id, users(id, first_name_ar, last_name_ar, roles(name_ar))')
    .eq('company_id', req.session.companyId)
    .or(`and(sender_user_id.eq.${me},recipient_user_id.eq.${req.params.userId}),and(sender_user_id.eq.${req.params.userId},recipient_user_id.eq.${me})`)
    .order('created_at');
  if (error) return res.status(500).json({ message: error.message });
  res.json(data || []);
});

app.post('/api/staff-chat/dm/:userId', requireAuth, async (req, res) => {
  const sb = requireSupabase(res); if (!sb) return;
  const { data: peer } = await sb.from('users').select('id').eq('id', req.params.userId).eq('company_id', req.session.companyId).maybeSingle();
  if (!peer) return res.status(404).json({ message: 'المستخدم غير موجود' });
  const b = req.body || {};
  if (!b.body && !b.attachment_data) return res.status(400).json({ message: 'الرسالة فارغة' });
  const payload = {
    company_id: req.session.companyId, sender_user_id: req.session.userId, recipient_user_id: req.params.userId,
    body: b.body || null, attachment_name: b.attachment_name || null, attachment_mime: b.attachment_mime || null, attachment_data: b.attachment_data || null,
  };
  const { data, error } = await sb.from('staff_messages').insert(payload)
    .select('id, body, attachment_name, attachment_mime, attachment_data, created_at, sender_user_id, recipient_user_id, users(id, first_name_ar, last_name_ar, roles(name_ar))').single();
  if (error) return res.status(500).json({ message: error.message });
  res.json(data);
});

// دليل الدردشات (صفحة "الدردشات") — عملاء كمجموعات + زملاء للمراسلة الخاصة + مجموعة المكتب
app.get('/api/chats', requireAuth, async (req, res) => {
  const sb = requireSupabase(res); if (!sb) return;
  const companyId = req.session.companyId;

  const { data: clients, error: clientsErr } = await sb.from('clients').select('id, name').eq('company_id', companyId).order('name');
  if (clientsErr) return res.status(500).json({ message: clientsErr.message });
  const clientIds = (clients || []).map(c => c.id);
  let lastByClient = {};
  if (clientIds.length) {
    const { data: lastMsgs } = await sb.from('chat_messages').select('client_id, body, created_at').in('client_id', clientIds).order('created_at', { ascending: false });
    (lastMsgs || []).forEach(m => { if (!lastByClient[m.client_id]) lastByClient[m.client_id] = m; });
  }
  const clientRooms = (clients || [])
    .map(c => ({ client_id: c.id, client_name: c.name, last_message: lastByClient[c.id] ? lastByClient[c.id].body : null, last_message_at: lastByClient[c.id] ? lastByClient[c.id].created_at : null }))
    .sort((a, b) => new Date(b.last_message_at || 0) - new Date(a.last_message_at || 0));

  const { data: colleagues } = await sb.from('users').select('id, first_name_ar, last_name_ar, roles(name_ar)').eq('company_id', companyId).neq('id', req.session.userId).order('first_name_ar');
  const colleagueIds = (colleagues || []).map(u => u.id);
  let lastByColleague = {};
  if (colleagueIds.length) {
    const { data: dms } = await sb.from('staff_messages').select('sender_user_id, recipient_user_id, body, created_at')
      .eq('company_id', companyId).not('recipient_user_id', 'is', null)
      .or(`sender_user_id.eq.${req.session.userId},recipient_user_id.eq.${req.session.userId}`).order('created_at', { ascending: false });
    (dms || []).forEach(m => {
      const peerId = m.sender_user_id === req.session.userId ? m.recipient_user_id : m.sender_user_id;
      if (!lastByColleague[peerId]) lastByColleague[peerId] = m;
    });
  }
  const staffDms = (colleagues || [])
    .map(u => ({ user_id: u.id, name: ((u.first_name_ar || '') + ' ' + (u.last_name_ar || '')).trim(), role: u.roles ? u.roles.name_ar : null, last_message: lastByColleague[u.id] ? lastByColleague[u.id].body : null, last_message_at: lastByColleague[u.id] ? lastByColleague[u.id].created_at : null }))
    .sort((a, b) => new Date(b.last_message_at || 0) - new Date(a.last_message_at || 0));

  const { data: lastGroupMsg } = await sb.from('staff_messages').select('body, created_at').eq('company_id', companyId).is('recipient_user_id', null).is('group_id', null).order('created_at', { ascending: false }).limit(1).maybeSingle();

  const { data: myMemberships } = await sb.from('staff_chat_group_members').select('group_id').eq('user_id', req.session.userId);
  const groupIds = (myMemberships || []).map(m => m.group_id);
  let staffGroups = [];
  if (groupIds.length) {
    const { data: groups } = await sb.from('staff_chat_groups').select('id, name').in('id', groupIds);
    const { data: lastMsgs } = await sb.from('staff_messages').select('group_id, body, created_at').in('group_id', groupIds).order('created_at', { ascending: false });
    const lastByGroup = {}; (lastMsgs || []).forEach(m => { if (!lastByGroup[m.group_id]) lastByGroup[m.group_id] = m; });
    staffGroups = (groups || []).map(g => ({ id: g.id, name: g.name, last_message: lastByGroup[g.id] ? lastByGroup[g.id].body : null, last_message_at: lastByGroup[g.id] ? lastByGroup[g.id].created_at : null }))
      .sort((a, b) => new Date(b.last_message_at || 0) - new Date(a.last_message_at || 0));
  }

  res.json({
    clientRooms,
    staffDms,
    staffGroups,
    staffGroup: { last_message: lastGroupMsg ? lastGroupMsg.body : null, last_message_at: lastGroupMsg ? lastGroupMsg.created_at : null },
  });
});

// يحفظ نسخة جديدة كاملة من بنود الميزان (إصدار جديد في كل مرة، بدون حذف الإصدارات السابقة)
app.post('/api/client-files/:id/trial-balance', requireAuth, async (req, res) => {
  const sb = requireSupabase(res); if (!sb) return;
  const file = await assertFileInCompany(sb, req.params.id, req.session.companyId);
  if (!file) return res.status(404).json({ message: 'الملف غير موجود' });
  const lines = Array.isArray(req.body.lines) ? req.body.lines : [];

  const { data: prev } = await sb.from('trial_balances').select('version').eq('client_file_id', req.params.id).order('version', { ascending: false }).limit(1).maybeSingle();
  const nextVersion = prev ? prev.version + 1 : 1;

  const { data: tb, error: tbErr } = await sb.from('trial_balances')
    .insert({ client_file_id: req.params.id, version: nextVersion, status: 'matched', uploaded_by: req.session.userId, file_url: req.body.fileUrl || null })
    .select().single();
  if (tbErr) return res.status(500).json({ message: tbErr.message });

  if (lines.length) {
    const rows = lines.map(l => ({
      trial_balance_id: tb.id,
      account_code: l.account_code,
      account_name: l.account_name || null,
      coa_account_id: l.coa_account_id || null,
      opening_balance: l.opening_balance || 0,
      debit_movement: l.debit_movement || 0,
      credit_movement: l.credit_movement || 0,
      closing_balance: l.closing_balance || 0,
    }));
    const { error: linesErr } = await sb.from('trial_balance_lines').insert(rows);
    if (linesErr) return res.status(500).json({ message: linesErr.message });
  }
  res.json({ trialBalance: tb });
});

// ---------------------------------------------------------------------------
// تحديث أوراق العمل (المطابقة التلقائية بالميزان + دليل الحسابات)
// ---------------------------------------------------------------------------
app.post('/api/client-files/:id/refresh-working-papers', requireAuth, async (req, res) => {
  const sb = requireSupabase(res); if (!sb) return;
  const file = await assertFileInCompany(sb, req.params.id, req.session.companyId);
  if (!file) return res.status(404).json({ message: 'الملف غير موجود' });
  const { error } = await sb.rpc('fn_refresh_client_file_working_papers', { p_client_file_id: req.params.id });
  if (error) return res.status(500).json({ message: error.message });
  await autoMatchRequirementTemplates(sb, req.params.id, req.session.companyId, req.session.userId);
  res.json({ ok: true });
});

// يطابق قوالب المتطلبات العامة مع حسابات الميزان الفعلية لهذا الملف ويضيف الناقص فقط (بدون تكرار)
async function autoMatchRequirementTemplates(sb, clientFileId, companyId, userId) {
  const { data: templates } = await sb.from('wp_requirement_templates').select('*').eq('company_id', companyId).eq('is_active', true);
  if (!templates || !templates.length) return;
  const { data: latestTb } = await sb.from('trial_balances').select('id').eq('client_file_id', clientFileId).order('version', { ascending: false }).limit(1).maybeSingle();
  let tbAccountIds = new Set();
  if (latestTb) {
    const { data: lines } = await sb.from('trial_balance_lines').select('coa_account_id').eq('trial_balance_id', latestTb.id).not('coa_account_id', 'is', null);
    (lines || []).forEach(l => tbAccountIds.add(l.coa_account_id));
  }
  const eligible = templates.filter(t => !t.coa_account_id || tbAccountIds.has(t.coa_account_id));
  if (!eligible.length) return;
  const { data: existing } = await sb.from('wp_requirements').select('template_id').eq('client_file_id', clientFileId).not('template_id', 'is', null);
  const existingTplIds = new Set((existing || []).map(e => e.template_id));
  const { data: file } = await sb.from('client_files').select('client_id').eq('id', clientFileId).maybeSingle();
  for (const t of eligible) {
    if (existingTplIds.has(t.id)) continue;
    const { data: newReq } = await sb.from('wp_requirements').insert({
      client_file_id: clientFileId, title: t.title, template_id: t.id, created_by: userId,
    }).select().single();
    if (newReq && file) {
      const { data: msg } = await sb.from('chat_messages').insert({
        company_id: companyId, client_id: file.client_id, client_file_id: clientFileId,
        sender_user_id: userId, body: '📋 طلب مرفق (تلقائي): ' + t.title, requirement_id: newReq.id,
      }).select('id').single();
      if (msg) await sb.from('wp_requirements').update({ chat_message_id: msg.id }).eq('id', newReq.id);
    }
  }
}

// ---------------------------------------------------------------------------
// تهيئة قوالب المتطلبات التلقائية (شبيهة تمامًا بتهيئة أوراق العمل)
// ---------------------------------------------------------------------------
app.get('/api/requirement-templates', requireAuth, async (req, res) => {
  const sb = requireSupabase(res); if (!sb) return;
  const { data, error } = await sb.from('wp_requirement_templates').select('*, chart_of_accounts(code, name_ar)').eq('company_id', req.session.companyId).order('created_at', { ascending: false });
  if (error) return res.status(500).json({ message: error.message });
  res.json(data || []);
});

app.post('/api/requirement-templates', requireAuth, async (req, res) => {
  const sb = requireSupabase(res); if (!sb) return;
  const b = req.body || {};
  if (!b.title || !b.title.trim()) return res.status(400).json({ message: 'اسم القالب إلزامي' });
  const payload = { company_id: req.session.companyId, title: b.title.trim(), coa_account_id: b.coa_account_id || null, visibility: b.coa_account_id ? 'general' : 'general' };
  const { data, error } = await sb.from('wp_requirement_templates').insert(payload).select().single();
  if (error) return res.status(500).json({ message: error.message });
  res.json(data);
});

app.put('/api/requirement-templates/:id', requireAuth, async (req, res) => {
  const sb = requireSupabase(res); if (!sb) return;
  const b = req.body || {};
  const payload = { title: b.title, coa_account_id: b.coa_account_id || null, is_active: b.is_active !== false };
  const { data, error } = await sb.from('wp_requirement_templates').update(payload).eq('id', req.params.id).eq('company_id', req.session.companyId).select().single();
  if (error) return res.status(500).json({ message: error.message });
  res.json(data);
});

app.delete('/api/requirement-templates/:id', requireAuth, async (req, res) => {
  const sb = requireSupabase(res); if (!sb) return;
  const { error } = await sb.from('wp_requirement_templates').delete().eq('id', req.params.id).eq('company_id', req.session.companyId);
  if (error) return res.status(500).json({ message: error.message });
  res.json({ ok: true });
});

app.get('/api/client-files/:id/working-papers', requireAuth, async (req, res) => {
  const sb = requireSupabase(res); if (!sb) return;
  const file = await assertFileInCompany(sb, req.params.id, req.session.companyId);
  if (!file) return res.status(404).json({ message: 'الملف غير موجود' });

  const { data: matched, error } = await sb.from('client_file_working_papers')
    .select('id, include_reason, status, wp_main_item_id, wp_main_items(id, code, title, objective, group_id, wp_groups(id, code, name, coa_account_id))')
    .eq('client_file_id', req.params.id)
    .eq('is_included', true);
  if (error) return res.status(500).json({ message: error.message });

  // نجيب آخر ميزان مراجعة ونربط كل ورقة رئيسية بمبلغ الحساب المرتبط بمجموعتها (إن وجد)
  const { data: latestTb } = await sb.from('trial_balances').select('id').eq('client_file_id', req.params.id).order('version', { ascending: false }).limit(1).maybeSingle();
  let amountByAccountId = {};
  if (latestTb) {
    const coaIds = [...new Set((matched || []).map(m => m.wp_main_items && m.wp_main_items.wp_groups && m.wp_main_items.wp_groups.coa_account_id).filter(Boolean))];
    if (coaIds.length) {
      const { data: coaRows } = await sb.from('chart_of_accounts').select('id, code').in('id', coaIds);
      const codeById = {}; (coaRows || []).forEach(c => codeById[c.id] = c.code);
      const codes = Object.values(codeById);
      if (codes.length) {
        const { data: lines } = await sb.from('trial_balance_lines').select('account_code, closing_balance').eq('trial_balance_id', latestTb.id).in('account_code', codes);
        const closingByCode = {}; (lines || []).forEach(l => closingByCode[l.account_code] = l.closing_balance);
        coaIds.forEach(id => { const code = codeById[id]; if (code !== undefined && closingByCode[code] !== undefined) amountByAccountId[id] = closingByCode[code]; });
      }
    }
  }
  const withAmounts = (matched || []).map(m => {
    const coaId = m.wp_main_items && m.wp_main_items.wp_groups && m.wp_main_items.wp_groups.coa_account_id;
    return { ...m, account_amount: coaId && amountByAccountId[coaId] !== undefined ? amountByAccountId[coaId] : null };
  });
  res.json(withAmounts);
});

app.get('/api/client-files/:id/wp-main-items/:mainId', requireAuth, async (req, res) => {
  const sb = requireSupabase(res); if (!sb) return;
  const file = await assertFileInCompany(sb, req.params.id, req.session.companyId);
  if (!file) return res.status(404).json({ message: 'الملف غير موجود' });
  const { data: main } = await sb.from('wp_main_items').select('*').eq('id', req.params.mainId).maybeSingle();
  if (!main) return res.status(404).json({ message: 'الورقة غير موجودة' });
  const { data: allSubs } = await sb.from('wp_sub_items').select('*').eq('main_item_id', req.params.mainId).order('sort_order');

  // فلترة البنود الفرعية "الخاصة" حسب نوع/قطاع عميل هذا الملف تحديدًا
  const { data: client } = await sb.from('clients').select('client_type_id, sector_id').eq('id', file.client_id).maybeSingle();
  let subs = allSubs || [];
  const specialIds = subs.filter(s => s.visibility === 'special').map(s => s.id);
  if (specialIds.length) {
    const { data: targets } = await sb.from('wp_visibility_targets').select('*').eq('entity_type', 'sub').in('entity_id', specialIds);
    subs = subs.filter(s => {
      if (s.visibility !== 'special') return true;
      const myTargets = (targets || []).filter(t => t.entity_id === s.id);
      if (!myTargets.length) return false; // خاص بدون أي هدف = لا يظهر لأحد
      return myTargets.some(t =>
        (!t.client_type_id || t.client_type_id === (client && client.client_type_id)) &&
        (!t.sector_id || t.sector_id === (client && client.sector_id))
      );
    });
  }

  const { data: answers } = await sb.from('client_file_wp_answers').select('*').eq('client_file_id', req.params.id).in('wp_sub_item_id', subs.map(s => s.id));
  const { data: signoffs } = await sb.from('wp_item_signoffs')
    .select('signoff_type, signed_at, users(id, first_name_ar, last_name_ar)')
    .eq('client_file_id', req.params.id).eq('wp_main_item_id', req.params.mainId);
  const { data: cfwp } = await sb.from('client_file_working_papers').select('not_applicable')
    .eq('client_file_id', req.params.id).eq('wp_main_item_id', req.params.mainId).maybeSingle();
  res.json({ main, subs, answers: answers || [], signoffs: signoffs || [], not_applicable: cfwp ? cfwp.not_applicable : false });
});

app.post('/api/client-files/:id/wp-main-items/:mainId/signoff', requireAuth, async (req, res) => {
  const sb = requireSupabase(res); if (!sb) return;
  const file = await assertFileInCompany(sb, req.params.id, req.session.companyId);
  if (!file) return res.status(404).json({ message: 'الملف غير موجود' });
  const type = req.body.signoff_type;
  if (!['prepared', 'updated', 'reviewed', 'approved'].includes(type)) return res.status(400).json({ message: 'نوع توقيع غير صالح' });
  if (req.body.checked) {
    const { error } = await sb.from('wp_item_signoffs')
      .upsert({ client_file_id: req.params.id, wp_main_item_id: req.params.mainId, signoff_type: type, user_id: req.session.userId, signed_at: new Date().toISOString() },
        { onConflict: 'client_file_id,wp_main_item_id,signoff_type' });
    if (error) return res.status(500).json({ message: error.message });
  } else {
    const { error } = await sb.from('wp_item_signoffs').delete()
      .eq('client_file_id', req.params.id).eq('wp_main_item_id', req.params.mainId).eq('signoff_type', type);
    if (error) return res.status(500).json({ message: error.message });
  }
  res.json({ ok: true });
});

app.post('/api/client-files/:id/wp-main-items/:mainId/toggle-na', requireAuth, async (req, res) => {
  const sb = requireSupabase(res); if (!sb) return;
  const file = await assertFileInCompany(sb, req.params.id, req.session.companyId);
  if (!file) return res.status(404).json({ message: 'الملف غير موجود' });
  const { error } = await sb.from('client_file_working_papers')
    .update({ not_applicable: !!req.body.not_applicable })
    .eq('client_file_id', req.params.id).eq('wp_main_item_id', req.params.mainId);
  if (error) return res.status(500).json({ message: error.message });
  res.json({ ok: true });
});

app.post('/api/client-files/:id/wp-answers', requireAuth, async (req, res) => {
  const sb = requireSupabase(res); if (!sb) return;
  const file = await assertFileInCompany(sb, req.params.id, req.session.companyId);
  if (!file) return res.status(404).json({ message: 'الملف غير موجود' });
  const answers = Array.isArray(req.body.answers) ? req.body.answers : [];
  for (const a of answers) {
    const payload = {
      client_file_id: req.params.id, wp_sub_item_id: a.wp_sub_item_id,
      answer_value: a.answer_value ?? null, comment: a.comment || null,
      not_applicable: !!a.not_applicable,
      answered_by: req.session.userId, answered_at: new Date().toISOString(),
    };
    if (a.attachment_url !== undefined) payload.attachment_url = a.attachment_url;
    const { error } = await sb.from('client_file_wp_answers')
      .upsert(payload, { onConflict: 'client_file_id,wp_sub_item_id' });
    if (error) return res.status(500).json({ message: error.message });
  }
  // يحدّث حالة الورقة الرئيسية إلى "قيد التنفيذ" تلقائيًا عند أول إجابة
  if (answers.length && req.body.mainItemId) {
    await sb.from('client_file_working_papers')
      .update({ status: 'in_progress' })
      .eq('client_file_id', req.params.id).eq('wp_main_item_id', req.body.mainItemId).eq('status', 'not_started');
  }
  res.json({ ok: true });
});

// ---------------------------------------------------------------------------
// نسبة الإنجاز — لكل ورقة رئيسية ولكامل الملف (البنود "لا ينطبق" لا تُحتسب)
// ---------------------------------------------------------------------------
app.get('/api/client-files/:id/progress', requireAuth, async (req, res) => {
  const sb = requireSupabase(res); if (!sb) return;
  const file = await assertFileInCompany(sb, req.params.id, req.session.companyId);
  if (!file) return res.status(404).json({ message: 'الملف غير موجود' });

  const { data: matched } = await sb.from('client_file_working_papers')
    .select('wp_main_item_id, not_applicable, status').eq('client_file_id', req.params.id).eq('is_included', true);
  const mainIds = (matched || []).map(m => m.wp_main_item_id);
  if (!mainIds.length) return res.json({ overallPercent: 0, byMain: {} });

  const { data: allSubs } = await sb.from('wp_sub_items').select('id, main_item_id').in('main_item_id', mainIds);
  const { data: answers } = await sb.from('client_file_wp_answers').select('wp_sub_item_id, not_applicable, answer_value, comment')
    .eq('client_file_id', req.params.id).in('wp_sub_item_id', (allSubs || []).map(s => s.id));
  const answerBySub = {}; (answers || []).forEach(a => answerBySub[a.wp_sub_item_id] = a);

  const byMain = {};
  let totalDone = 0, totalCount = 0;
  mainIds.forEach(mainId => {
    const mRow = (matched || []).find(m => m.wp_main_item_id === mainId);
    const subs = (allSubs || []).filter(s => s.main_item_id === mainId);
    if (mRow && mRow.not_applicable) { byMain[mainId] = 100; return; }
    if (!subs.length) { byMain[mainId] = mRow && mRow.status === 'completed' ? 100 : 0; return; }
    let done = 0;
    subs.forEach(s => {
      const a = answerBySub[s.id];
      if (a && (a.not_applicable || a.answer_value !== null || (a.comment && a.comment.trim()))) done++;
    });
    byMain[mainId] = Math.round((done / subs.length) * 100);
    totalDone += done; totalCount += subs.length;
  });
  const overallPercent = totalCount ? Math.round((totalDone / totalCount) * 100) : 0;
  res.json({ overallPercent, byMain });
});

// ---------------------------------------------------------------------------
// المستخدمون (موظفو المكتب)
// ---------------------------------------------------------------------------
app.get('/api/users', requireAuth, async (req, res) => {
  const sb = requireSupabase(res); if (!sb) return;
  const { data, error } = await sb.from('users')
    .select('id, first_name_ar, last_name_ar, phone, email, job_title_ar, is_sales_agent, is_active, username, branch_id, role_id, roles(code, name_ar), branches(name)')
    .eq('company_id', req.session.companyId)
    .order('created_at', { ascending: false });
  if (error) return res.status(500).json({ message: error.message });
  res.json(data);
});

app.post('/api/users', requireAuth, async (req, res) => {
  const sb = requireSupabase(res); if (!sb) return;
  const body = req.body || {};
  if (!body.username || !body.first_name_ar || !body.last_name_ar || !body.role_id) {
    return res.status(400).json({ message: 'الاسم واسم المستخدم والدور إلزامية' });
  }
  const tempPassword = body.password || Math.random().toString(36).slice(-8);
  const passwordHash = await bcrypt.hash(tempPassword, 10);
  const payload = {
    company_id: req.session.companyId,
    branch_id: body.branch_id || null, role_id: body.role_id,
    first_name_ar: body.first_name_ar, last_name_ar: body.last_name_ar,
    first_name_en: body.first_name_en || null, last_name_en: body.last_name_en || null,
    phone: body.phone || null, gender: body.gender || null,
    job_title_ar: body.job_title_ar || null, job_title_en: body.job_title_en || null,
    employment_type: body.employment_type || null, is_sales_agent: !!body.is_sales_agent,
    username: body.username, email: body.email || null,
    password_hash: passwordHash, is_active: true,
  };
  const { data, error } = await sb.from('users').insert(payload).select().single();
  if (error) return res.status(500).json({ message: error.message });
  res.json({ ...data, temporaryPassword: body.password ? undefined : tempPassword });
});

app.get('/api/users/:id', requireAuth, async (req, res) => {
  const sb = requireSupabase(res); if (!sb) return;
  const { data, error } = await sb.from('users').select('*')
    .eq('id', req.params.id).eq('company_id', req.session.companyId).maybeSingle();
  if (error) return res.status(500).json({ message: error.message });
  if (!data) return res.status(404).json({ message: 'المستخدم غير موجود' });
  res.json(data);
});

app.put('/api/users/:id', requireAuth, async (req, res) => {
  const sb = requireSupabase(res); if (!sb) return;
  const { data: existing } = await sb.from('users').select('id').eq('id', req.params.id).eq('company_id', req.session.companyId).maybeSingle();
  if (!existing) return res.status(404).json({ message: 'المستخدم غير موجود' });
  const body = req.body || {};
  const payload = {
    branch_id: body.branch_id || null, role_id: body.role_id,
    first_name_ar: body.first_name_ar, last_name_ar: body.last_name_ar,
    first_name_en: body.first_name_en || null, last_name_en: body.last_name_en || null,
    phone: body.phone || null, gender: body.gender || null,
    job_title_ar: body.job_title_ar || null, job_title_en: body.job_title_en || null,
    employment_type: body.employment_type || null, is_sales_agent: !!body.is_sales_agent,
    email: body.email || null, is_active: body.is_active !== false,
  };
  if (body.password) payload.password_hash = await bcrypt.hash(body.password, 10);
  const { data, error } = await sb.from('users').update(payload).eq('id', req.params.id).select().single();
  if (error) return res.status(500).json({ message: error.message });
  res.json(data);
});

// ---------------------------------------------------------------------------
// فريق المراجعة المرتبط بكل عميل
// ---------------------------------------------------------------------------
app.get('/api/clients/:id/reviewers', requireAuth, async (req, res) => {
  const sb = requireSupabase(res); if (!sb) return;
  const { data: client } = await sb.from('clients').select('id').eq('id', req.params.id).eq('company_id', req.session.companyId).maybeSingle();
  if (!client) return res.status(404).json({ message: 'العميل غير موجود' });
  const { data, error } = await sb.from('client_reviewer_assignments')
    .select('id, user_id, users(id, first_name_ar, last_name_ar, roles(name_ar))')
    .eq('client_id', req.params.id);
  if (error) return res.status(500).json({ message: error.message });
  res.json(data || []);
});

app.post('/api/clients/:id/reviewers', requireAuth, async (req, res) => {
  const sb = requireSupabase(res); if (!sb) return;
  const { data: client } = await sb.from('clients').select('id').eq('id', req.params.id).eq('company_id', req.session.companyId).maybeSingle();
  if (!client) return res.status(404).json({ message: 'العميل غير موجود' });
  const { data: user } = await sb.from('users').select('id').eq('id', req.body.user_id).eq('company_id', req.session.companyId).maybeSingle();
  if (!user) return res.status(400).json({ message: 'المستخدم غير موجود ضمن مكتبك' });
  const { error } = await sb.from('client_reviewer_assignments').insert({ client_id: req.params.id, user_id: req.body.user_id });
  if (error) return res.status(500).json({ message: error.message });
  res.json({ ok: true });
});

app.delete('/api/clients/:id/reviewers/:userId', requireAuth, async (req, res) => {
  const sb = requireSupabase(res); if (!sb) return;
  const { data: client } = await sb.from('clients').select('id').eq('id', req.params.id).eq('company_id', req.session.companyId).maybeSingle();
  if (!client) return res.status(404).json({ message: 'العميل غير موجود' });
  const { error } = await sb.from('client_reviewer_assignments').delete()
    .eq('client_id', req.params.id).eq('user_id', req.params.userId);
  if (error) return res.status(500).json({ message: error.message });
  res.json({ ok: true });
});

// ---------------------------------------------------------------------------
// ميزان المراجعة: تنزيل نموذج فارغ (بقائمة منسدلة لدليل الحسابات مستوى 4) وتصدير الحالي
// ---------------------------------------------------------------------------
app.get('/api/client-files/:id/trial-balance/template', requireAuth, async (req, res) => {
  try {
    const sb = requireSupabase(res); if (!sb) return;
    const file = await assertFileInCompany(sb, req.params.id, req.session.companyId);
    if (!file) return res.status(404).json({ message: 'الملف غير موجود' });
    const { data: coa, error: coaErr } = await sb.from('chart_of_accounts').select('code, name_ar')
      .eq('company_id', req.session.companyId).eq('level', 4).order('code');
    if (coaErr) return res.status(500).json({ message: 'تعذّر تحميل دليل الحسابات: ' + coaErr.message });

    const wb = new ExcelJS.Workbook();
    const ws = wb.addWorksheet('ميزان المراجعة');
    ws.views = [{ rightToLeft: true }];
    ws.columns = [
      { header: 'رقم الحساب', key: 'code', width: 16 },
      { header: 'اسم الحساب', key: 'name', width: 26 },
      { header: 'رصيد أول الفترة', key: 'opening', width: 18 },
      { header: 'مدين الحركة', key: 'debit', width: 16 },
      { header: 'دائن الحركة', key: 'credit', width: 16 },
      { header: 'رصيد آخر الفترة', key: 'closing', width: 18 },
      { header: 'رمز المستوى الرابع بدليل الحسابات', key: 'coaCode', width: 30 },
    ];
    ws.getRow(1).font = { bold: true };

    const coaList = wb.addWorksheet('دليل الحسابات (لا تُعدَّل)');
    coaList.state = 'veryHidden';
    (coa || []).forEach((a, i) => { coaList.getCell(`A${i + 1}`).value = `${a.code} — ${a.name_ar}`; });
    const lastRow = Math.max((coa || []).length, 1);

    for (let r = 2; r <= 200; r++) {
      ws.getCell(`G${r}`).dataValidation = {
        type: 'list', allowBlank: true,
        formulae: [`'دليل الحسابات (لا تُعدَّل)'!$A$1:$A$${lastRow}`],
      };
    }

    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.setHeader('Content-Disposition', "attachment; filename=\"trial-balance-template.xlsx\"; filename*=UTF-8''" + encodeURIComponent('نموذج-ميزان-المراجعة.xlsx'));
    await wb.xlsx.write(res);
    res.end();
  } catch (e) {
    console.error('trial-balance/template failed:', e);
    if (!res.headersSent) res.status(500).json({ message: 'تعذّر إنشاء ملف النموذج: ' + e.message });
    else res.end();
  }
});

app.get('/api/client-files/:id/trial-balance/export', requireAuth, async (req, res) => {
  try {
    const sb = requireSupabase(res); if (!sb) return;
    const file = await assertFileInCompany(sb, req.params.id, req.session.companyId);
    if (!file) return res.status(404).json({ message: 'الملف غير موجود' });
    const { data: latest, error: latestErr } = await sb.from('trial_balances').select('*').eq('client_file_id', req.params.id).order('version', { ascending: false }).limit(1).maybeSingle();
    if (latestErr) return res.status(500).json({ message: 'تعذّر تحميل الميزان: ' + latestErr.message });
    let lines = [];
    if (latest) {
      const { data, error: linesErr } = await sb.from('trial_balance_lines').select('*, chart_of_accounts(code, name_ar)').eq('trial_balance_id', latest.id).order('account_code');
      if (linesErr) return res.status(500).json({ message: 'تعذّر تحميل بنود الميزان: ' + linesErr.message });
      lines = data || [];
    }

    const wb = new ExcelJS.Workbook();
    const ws = wb.addWorksheet('ميزان المراجعة');
    ws.views = [{ rightToLeft: true }];
    ws.columns = [
      { header: 'رقم الحساب', key: 'code', width: 16 },
      { header: 'اسم الحساب', key: 'name', width: 26 },
      { header: 'رصيد أول الفترة', key: 'opening', width: 18 },
      { header: 'مدين الحركة', key: 'debit', width: 16 },
      { header: 'دائن الحركة', key: 'credit', width: 16 },
      { header: 'رصيد آخر الفترة', key: 'closing', width: 18 },
      { header: 'المستوى الرابع — دليل الحسابات', key: 'coa', width: 30 },
    ];
    ws.getRow(1).font = { bold: true };
    lines.forEach(l => ws.addRow({
      code: l.account_code, name: l.account_name,
      opening: l.opening_balance, debit: l.debit_movement, credit: l.credit_movement, closing: l.closing_balance,
      coa: l.chart_of_accounts ? `${l.chart_of_accounts.code} — ${l.chart_of_accounts.name_ar}` : '',
    }));

    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.setHeader('Content-Disposition', "attachment; filename=\"trial-balance.xlsx\"; filename*=UTF-8''" + encodeURIComponent('ميزان-المراجعة.xlsx'));
    await wb.xlsx.write(res);
    res.end();
  } catch (e) {
    console.error('trial-balance/export failed:', e);
    if (!res.headersSent) res.status(500).json({ message: 'تعذّر تصدير الملف: ' + e.message });
    else res.end();
  }
});

// ---------------------------------------------------------------------------
app.get('/healthz', (req, res) => res.status(200).send('ok'));
app.use(express.static(path.join(__dirname, 'public')));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.listen(PORT, () => console.log(`تمام يعمل الآن على المنفذ ${PORT}`));
