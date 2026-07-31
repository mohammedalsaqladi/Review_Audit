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

const app = express();
app.use(express.json());

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

app.get('/api/wp-main-items/:id', requireAuth, async (req, res) => {
  const sb = requireSupabase(res); if (!sb) return;
  const { data: main, error: e1 } = await sb.from('wp_main_items').select('*')
    .eq('id', req.params.id).eq('company_id', req.session.companyId).maybeSingle();
  if (e1) return res.status(500).json({ message: e1.message });
  if (!main) return res.status(404).json({ message: 'الورقة غير موجودة' });
  const { data: subs, error: e2 } = await sb.from('wp_sub_items').select('*')
    .eq('main_item_id', req.params.id).order('sort_order');
  if (e2) return res.status(500).json({ message: e2.message });
  res.json({ main, subs });
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
  res.json(data);
});

app.post('/api/wp-main-items', requireAuth, async (req, res) => {
  const sb = requireSupabase(res); if (!sb) return;
  // تأكد أن المجموعة تتبع نفس مكتب المستخدم الحالي قبل الإدراج
  const { data: group } = await sb.from('wp_groups').select('id')
    .eq('id', req.body.group_id).eq('company_id', req.session.companyId).maybeSingle();
  if (!group) return res.status(400).json({ message: 'المجموعة غير موجودة أو لا تتبع مكتبك' });
  const payload = { ...req.body, company_id: req.session.companyId };
  const { data, error } = await sb.from('wp_main_items').insert(payload).select().single();
  if (error) return res.status(500).json({ message: error.message });
  res.json(data);
});

app.post('/api/wp-sub-items', requireAuth, async (req, res) => {
  const sb = requireSupabase(res); if (!sb) return;
  const { data: main } = await sb.from('wp_main_items').select('id')
    .eq('id', req.body.main_item_id).eq('company_id', req.session.companyId).maybeSingle();
  if (!main) return res.status(400).json({ message: 'الورقة الرئيسية غير موجودة أو لا تتبع مكتبك' });
  const payload = { ...req.body, company_id: req.session.companyId };
  const { data, error } = await sb.from('wp_sub_items').insert(payload).select().single();
  if (error) return res.status(500).json({ message: error.message });
  res.json(data);
});

// ---------------------------------------------------------------------------
app.get('/healthz', (req, res) => res.status(200).send('ok'));
app.use(express.static(path.join(__dirname, 'public')));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.listen(PORT, () => console.log(`تمام يعمل الآن على المنفذ ${PORT}`));
