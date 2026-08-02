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
  const payload = {
    client_file_id: req.params.id,
    coa_account_id: b.coa_account_id || null,
    account_code: b.account_code || null,
    account_name: b.account_name || null,
    debit: Number(b.debit) || 0,
    credit: Number(b.credit) || 0,
    description: b.description || null,
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
  const payload = {
    coa_account_id: b.coa_account_id || null,
    account_code: b.account_code || null,
    account_name: b.account_name || null,
    debit: Number(b.debit) || 0,
    credit: Number(b.credit) || 0,
    description: b.description || null,
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
// نظام الدردشة — غرفة عامة واحدة لكل ملف تدقيق (وفريق المراجعة)، مع إمكانية
// دردشة خاصة ببند عمل رئيسي عبر تمرير wp_main_item_id
// ---------------------------------------------------------------------------
app.get('/api/client-files/:id/chat', requireAuth, async (req, res) => {
  const sb = requireSupabase(res); if (!sb) return;
  const file = await assertFileInCompany(sb, req.params.id, req.session.companyId);
  if (!file) return res.status(404).json({ message: 'الملف غير موجود' });
  let q = sb.from('chat_messages')
    .select('id, body, attachment_name, attachment_mime, attachment_data, created_at, wp_main_item_id, sender_user_id, users(id, first_name_ar, last_name_ar)')
    .eq('client_file_id', req.params.id).order('created_at');
  if (req.query.mainItemId) q = q.eq('wp_main_item_id', req.query.mainItemId);
  else q = q.is('wp_main_item_id', null);
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
    client_file_id: req.params.id,
    wp_main_item_id: b.wp_main_item_id || null,
    sender_user_id: req.session.userId,
    body: b.body || null,
    attachment_name: b.attachment_name || null,
    attachment_mime: b.attachment_mime || null,
    attachment_data: b.attachment_data || null,
  };
  const { data, error } = await sb.from('chat_messages').insert(payload)
    .select('id, body, attachment_name, attachment_mime, attachment_data, created_at, wp_main_item_id, sender_user_id, users(id, first_name_ar, last_name_ar)')
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

// دليل غرف الدردشة المتاحة للمستخدم الحالي: كل ملف تدقيق هو "عميل/شركة" ← غرفة عامة لفريقها
app.get('/api/chats', requireAuth, async (req, res) => {
  const sb = requireSupabase(res); if (!sb) return;
  const { data: files, error } = await sb.from('client_files')
    .select('id, name, status, client_id, clients!inner(id, name, company_id)')
    .eq('clients.company_id', req.session.companyId).order('created_at', { ascending: false });
  if (error) return res.status(500).json({ message: error.message });
  const fileIds = (files || []).map(f => f.id);
  let lastByFile = {};
  if (fileIds.length) {
    const { data: lastMsgs } = await sb.from('chat_messages')
      .select('client_file_id, body, created_at').in('client_file_id', fileIds).is('wp_main_item_id', null)
      .order('created_at', { ascending: false });
    (lastMsgs || []).forEach(m => { if (!lastByFile[m.client_file_id]) lastByFile[m.client_file_id] = m; });
  }
  const rooms = (files || []).map(f => ({
    client_file_id: f.id, file_name: f.name, client_name: f.clients.name,
    last_message: lastByFile[f.id] ? lastByFile[f.id].body : null,
    last_message_at: lastByFile[f.id] ? lastByFile[f.id].created_at : null,
  }));
  res.json(rooms);
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
  res.json({ ok: true });
});

app.get('/api/client-files/:id/working-papers', requireAuth, async (req, res) => {
  const sb = requireSupabase(res); if (!sb) return;
  const file = await assertFileInCompany(sb, req.params.id, req.session.companyId);
  if (!file) return res.status(404).json({ message: 'الملف غير موجود' });

  const { data: matched, error } = await sb.from('client_file_working_papers')
    .select('id, include_reason, status, wp_main_item_id, wp_main_items(id, code, title, objective, group_id, wp_groups(id, code, name))')
    .eq('client_file_id', req.params.id)
    .eq('is_included', true);
  if (error) return res.status(500).json({ message: error.message });
  res.json(matched);
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
  res.json({ main, subs, answers: answers || [] });
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
      answered_by: req.session.userId, answered_at: new Date().toISOString(),
    };
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
