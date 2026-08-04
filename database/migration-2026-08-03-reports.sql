-- ============================================================================
-- تمام | ترقية قاعدة البيانات — وحدة "تقارير المراجعة"
-- التاريخ: 2026-08-03
-- نفّذ هذا الملف كاملًا مرة واحدة على Supabase (SQL Editor) بعد schema.sql
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 1) قاعدة تهيئة تقارير المراجعة (المكتبة النصية المعتمدة)
--    company_id = NULL  ⇒  بند من المكتبة العامة المتاحة لكل المكاتب
--    company_id = <id>  ⇒  بند خاص بالمكتب (إضافة جديدة أو نسخة معدّلة)
-- ----------------------------------------------------------------------------
create table if not exists audit_report_config (
    id              uuid primary key default gen_random_uuid(),
    company_id      uuid references companies(id) on delete cascade,
    report_kind     varchar(20)  not null,          -- annual (سنوي) / interim (مرحلي)
    opinion_type    varchar(20)  not null,          -- unmodified / qualified / adverse / disclaimer
    consolidation   varchar(20)  not null default 'both',  -- consolidated / standalone / both
    group_name      varchar(200) not null,          -- المجموعة (الرأي، أساس الرأي، ...)
    item_name       varchar(400),                   -- البند (اسم مختصر يميّز النص)
    body            text,                           -- البيان (النص المعتمد)
    code            varchar(30),                    -- الكود المرجعي في مكتبة المكتب
    lang            varchar(5)   not null default 'ar',
    section_order   int          not null default 100,   -- ترتيب الفقرة داخل التقرير
    selection_mode  varchar(10)  not null default 'single', -- single (فقرة واحدة) / multi (عدة صفوف)
    is_required     boolean      not null default false,
    is_active       boolean      not null default true,
    source_id       uuid references audit_report_config(id) on delete set null, -- أصل النسخة عند التبنّي
    created_by      uuid references users(id),
    created_at      timestamptz  not null default now(),
    updated_at      timestamptz  not null default now()
);
create index if not exists idx_arc_company on audit_report_config(company_id);
create index if not exists idx_arc_filter  on audit_report_config(report_kind, opinion_type, group_name);

drop trigger if exists trg_arc_updated_at on audit_report_config;
create trigger trg_arc_updated_at
    before update on audit_report_config
    for each row execute function fn_set_updated_at();

comment on table audit_report_config is 'قاعدة تهيئة تقارير المراجعة: نصوص الرأي وأساس الرأي والمسؤوليات والمتطلبات النظامية';


-- ----------------------------------------------------------------------------
-- 2) التقارير المُنشأة
-- ----------------------------------------------------------------------------
create table if not exists audit_reports (
    id               uuid primary key default gen_random_uuid(),
    company_id       uuid not null references companies(id) on delete cascade,
    client_id        uuid not null references clients(id)   on delete cascade,
    client_file_id   uuid references client_files(id) on delete set null,
    report_no        varchar(40),                   -- رقم التقرير/الملف الظاهر بالطباعة
    report_kind      varchar(20) not null,          -- annual / interim
    consolidation    varchar(20) not null default 'consolidated',
    opinion_type     varchar(20) not null,          -- unmodified / qualified / adverse / disclaimer
    period_start     date,
    period_end       date,
    report_date      date,
    place            varchar(120),                  -- المدينة (الرياض ...)
    addressee        text,                          -- "السادة/ الشركاء المحترمون"
    entity_type_text varchar(150),                  -- نوع الشركة (ذات مسؤولية محدودة ...)
    sections         jsonb not null default '[]'::jsonb,  -- فقرات التقرير القابلة للتحرير
    status           varchar(20) not null default 'draft',  -- draft (مسودة) / approved (معتمد من الشريك)
    approved_by      uuid references users(id),
    approved_at      timestamptz,
    signature_url    text,                          -- صورة التوقيع اليدوي
    stamp_url        text,                          -- صورة الختم
    partner_name     varchar(150),
    partner_license  varchar(50),
    public_token     varchar(48) unique,            -- يُستخدم في رابط الباركود QR
    created_by       uuid references users(id),
    created_at       timestamptz not null default now(),
    updated_at       timestamptz not null default now()
);
create index if not exists idx_audit_reports_company on audit_reports(company_id);
create index if not exists idx_audit_reports_client  on audit_reports(client_id);
create index if not exists idx_audit_reports_status  on audit_reports(status);

drop trigger if exists trg_audit_reports_updated_at on audit_reports;
create trigger trg_audit_reports_updated_at
    before update on audit_reports
    for each row execute function fn_set_updated_at();

comment on table audit_reports is 'تقارير المراجعة المُصدرة لكل عميل (مسودة/معتمدة) مع فقراتها القابلة للتحرير';


-- ----------------------------------------------------------------------------
-- 3) سجل اعتماد/إلغاء اعتماد التقرير (أثر تدقيقي)
-- ----------------------------------------------------------------------------
create table if not exists audit_report_events (
    id          uuid primary key default gen_random_uuid(),
    report_id   uuid not null references audit_reports(id) on delete cascade,
    action      varchar(30) not null,   -- created / updated / approved / unapproved / printed
    note        text,
    user_id     uuid references users(id),
    created_at  timestamptz not null default now()
);
create index if not exists idx_are_report on audit_report_events(report_id);


-- ----------------------------------------------------------------------------
-- 4) بيانات المكتب المستخدمة في ترويسة التقرير (إضافات على companies)
-- ----------------------------------------------------------------------------
alter table companies add column if not exists stamp_url        text;
alter table companies add column if not exists signature_url    text;
alter table companies add column if not exists report_footer_ar text;
alter table companies add column if not exists public_base_url  text;   -- يُستخدم في رابط الباركود


-- ----------------------------------------------------------------------------
-- 5) إعدادات تنسيق طباعة التقارير (خطوط، مقاسات، هوامش، نصوص المقدمة)
--    نفّذ هذا الجزء أيضًا إن كنت قد شغّلت الملف قبل التحديث
-- ----------------------------------------------------------------------------
alter table companies add column if not exists report_settings jsonb not null default '{}'::jsonb;
alter table companies add column if not exists signer_name     varchar(150);   -- اسم من يوقّع/يعتمد التقرير
alter table companies add column if not exists signer_title    varchar(150);


-- ============================================================================
-- تحديث 2026-08-04: مجموعات ديناميكية + أنواع تقرير/رأي من القاعدة + كود تلقائي
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 6) أنواع التقرير (سنوي/مرحلي/...) وأنواع الرأي — قابلة للإضافة من الواجهة
--    company_id = NULL ⇒ عام لكل المكاتب
-- ----------------------------------------------------------------------------
create table if not exists audit_report_kinds (
    id          uuid primary key default gen_random_uuid(),
    company_id  uuid references companies(id) on delete cascade,
    code        varchar(30) not null,     -- annual / interim / ...
    label_ar    varchar(100) not null,
    sort_order  int not null default 100,
    is_active   boolean not null default true,
    created_at  timestamptz not null default now()
);
create table if not exists audit_report_opinions (
    id          uuid primary key default gen_random_uuid(),
    company_id  uuid references companies(id) on delete cascade,
    report_kind varchar(30) not null,     -- يربط الرأي بنوع تقرير محدد (annual/interim/...)
    code        varchar(30) not null,     -- unmodified / qualified / adverse / disclaimer / ...
    label_ar    varchar(100) not null,
    sort_order  int not null default 100,
    is_active   boolean not null default true,
    created_at  timestamptz not null default now()
);

insert into audit_report_kinds (company_id, code, label_ar, sort_order) values
  (null,'annual','سنوي',10), (null,'interim','مرحلي / فحص',20)
on conflict do nothing;

insert into audit_report_opinions (company_id, report_kind, code, label_ar, sort_order) values
  (null,'annual','unmodified','غير معدل',10),
  (null,'annual','qualified','متحفظ',20),
  (null,'annual','adverse','معارض',30),
  (null,'annual','disclaimer','امتناع عن إبداء الرأي',40),
  (null,'interim','unmodified','استنتاج غير معدّل',10),
  (null,'interim','qualified','استنتاج متحفظ',20),
  (null,'interim','adverse','استنتاج معارض',30),
  (null,'interim','disclaimer','امتناع عن إبداء الاستنتاج',40)
on conflict do nothing;

-- ----------------------------------------------------------------------------
-- 7) مجموعات التقرير (البيانات الوصفية: الاسم، الترتيب، إلزامية، وضع الاختيار)
--    منفصلة عن نصوص المكتبة نفسها — تتحكم بالعرض والتركيب الآلي
-- ----------------------------------------------------------------------------
create table if not exists audit_report_groups (
    id              uuid primary key default gen_random_uuid(),
    company_id      uuid references companies(id) on delete cascade,
    report_kind     varchar(30) not null,
    group_name      varchar(200) not null,
    section_order   int not null default 100,
    selection_mode  varchar(10) not null default 'single',   -- single / multi
    is_required     boolean not null default false,
    is_active       boolean not null default true,
    source_id       uuid references audit_report_groups(id) on delete set null,
    created_by      uuid references users(id),
    created_at      timestamptz not null default now(),
    updated_at      timestamptz not null default now()
);
create index if not exists idx_arg_company on audit_report_groups(company_id);
create index if not exists idx_arg_kind on audit_report_groups(report_kind);

drop trigger if exists trg_arg_updated_at on audit_report_groups;
create trigger trg_arg_updated_at
    before update on audit_report_groups
    for each row execute function fn_set_updated_at();

insert into audit_report_groups (company_id, report_kind, group_name, section_order, selection_mode, is_required) values
  (null,'annual','الرأي المطلق',10,'single',true),
  (null,'annual','الرأي المتحفظ',10,'single',true),
  (null,'annual','الرأي المعارض',10,'single',true),
  (null,'annual','الرأي الإمتناع',10,'single',true),
  (null,'annual','أساس الرأي المطلق',20,'single',true),
  (null,'annual','أساس الرأي المتحفظ',20,'multi',true),
  (null,'annual','أساس الرأي المعارض',20,'multi',true),
  (null,'annual','أساس الامتناع عن إبداء رأي',20,'multi',true),
  (null,'annual','عدم التأكد الجوهري المتعلق بالاستمرارية',30,'single',false),
  (null,'annual','لفت انتباه – الأساس المحاسبي وتقييد التوزيع والاستخدام',40,'single',false),
  (null,'annual','أمر آخر',50,'multi',false),
  (null,'annual','مسؤوليات الإدارة والمكلفين بالحوكمة عن القوائم المالية',60,'single',true),
  (null,'annual','مسؤوليات المراجع عن مراجعة القوائم المالية',70,'single',true),
  (null,'annual','التقرير عن المتطلبات النظامية والتنظيمية الأخرى',80,'multi',false),
  (null,'interim','مقدمة',10,'single',true),
  (null,'interim','نطاق الفحص',20,'single',true),
  (null,'interim','أساس الاستنتاج المتحفظ',30,'multi',true),
  (null,'interim','أساس الاستنتاج المعارض',30,'multi',true),
  (null,'interim','أساس الامتناع عن إبداء استنتاج',30,'multi',true),
  (null,'interim','الاستنتاج',40,'single',true),
  (null,'interim','الاستنتاج المتحفظ',40,'single',true),
  (null,'interim','الاستنتاج المعارض',40,'single',true),
  (null,'interim','الامتناع عن إبداء استنتاج',40,'single',true)
on conflict do nothing;

-- ----------------------------------------------------------------------------
-- 8) كود تلقائي غير قابل للتعديل لكل بند في مكتبة النصوص
-- ----------------------------------------------------------------------------
create sequence if not exists audit_report_config_code_seq start 1;
alter table audit_report_config alter column code drop not null;

create or replace function fn_auto_code_report_config() returns trigger as $$
begin
  if new.code is null or new.code = '' then
    new.code := 'C' || lpad(nextval('audit_report_config_code_seq')::text, 5, '0');
  end if;
  return new;
end;
$$ language plpgsql;

drop trigger if exists trg_arc_auto_code on audit_report_config;
create trigger trg_arc_auto_code
    before insert on audit_report_config
    for each row execute function fn_auto_code_report_config();

-- ----------------------------------------------------------------------------
-- 9) موضع الباركود في الطباعة (يُخزَّن ضمن report_settings JSONB — لا حاجة لعمود جديد)
--    القيم المسموحة: top-center, top-left, bottom-center, bottom-left, bottom-right
-- ----------------------------------------------------------------------------

-- ----------------------------------------------------------------------------
-- 10) مرفقات العميل من البوابة (لا حذف ولا تعديل، إضافة فقط)
-- ----------------------------------------------------------------------------
alter table documents add column if not exists uploaded_by_client_employee_id uuid references client_employees(id);
