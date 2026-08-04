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
