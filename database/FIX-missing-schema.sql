-- ============================================================================
-- تمام | إصلاح فوري — تشغيل هذا الملف وحده يكفي لحل خطأ:
--   "Could not find the 'report_settings' column of 'companies'"
--   "Could not find the table 'public.audit_report_groups'"
-- السبب: هذه الإضافات وصلت في تحديث لاحق على ملف الهجرة الأصلي، ولم يُعَد تشغيلها.
-- الملف آمن للتشغيل أكثر من مرة (كل أمر فيه IF NOT EXISTS / ON CONFLICT DO NOTHING).
-- ============================================================================

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

create unique index if not exists uq_ark_global on audit_report_kinds(code) where company_id is null;
create unique index if not exists uq_ark_company on audit_report_kinds(company_id, code) where company_id is not null;

insert into audit_report_kinds (company_id, code, label_ar, sort_order) values
  (null,'annual','سنوي',10), (null,'interim','مرحلي / فحص',20)
on conflict (code) where company_id is null do nothing;

create unique index if not exists uq_aro_global on audit_report_opinions(report_kind, code) where company_id is null;
create unique index if not exists uq_aro_company on audit_report_opinions(company_id, report_kind, code) where company_id is not null;

insert into audit_report_opinions (company_id, report_kind, code, label_ar, sort_order) values
  (null,'annual','unmodified','غير معدل',10),
  (null,'annual','qualified','متحفظ',20),
  (null,'annual','adverse','معارض',30),
  (null,'annual','disclaimer','امتناع عن إبداء الرأي',40),
  (null,'interim','unmodified','استنتاج غير معدّل',10),
  (null,'interim','qualified','استنتاج متحفظ',20),
  (null,'interim','adverse','استنتاج معارض',30),
  (null,'interim','disclaimer','امتناع عن إبداء الاستنتاج',40)
on conflict (report_kind, code) where company_id is null do nothing;

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

create unique index if not exists uq_arg_global on audit_report_groups(report_kind, group_name) where company_id is null;
create unique index if not exists uq_arg_company on audit_report_groups(company_id, report_kind, group_name) where company_id is not null;

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
on conflict (report_kind, group_name) where company_id is null do nothing;

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


-- ============================================================================
-- تحديث 2026-08-04 (مساءً): مشاركة النماذج مع العملاء + ملاحظات بوابة العميل
-- ============================================================================

-- 11) هل يظهر النموذج الجاهز في بوابة العميل؟
alter table templates add column if not exists is_client_visible boolean not null default false;
alter table templates add column if not exists description text;
alter table templates add column if not exists sort_order int not null default 100;

-- 12) ملاحظات يراها العميل في بوابته (يكتبها المكتب)
create table if not exists client_notes (
    id             uuid primary key default gen_random_uuid(),
    company_id     uuid not null references companies(id) on delete cascade,
    client_id      uuid not null references clients(id) on delete cascade,
    client_file_id uuid references client_files(id) on delete set null,
    title          varchar(200),
    body           text not null,
    is_pinned      boolean not null default false,
    created_by     uuid references users(id),
    created_at     timestamptz not null default now(),
    updated_at     timestamptz not null default now()
);
create index if not exists idx_client_notes_client on client_notes(client_id);

drop trigger if exists trg_client_notes_updated_at on client_notes;
create trigger trg_client_notes_updated_at
    before update on client_notes
    for each row execute function fn_set_updated_at();
