-- ============================================================================
--  تمام | نظام المراجعة والتدقيق
--  قاعدة البيانات الرئيسية — PostgreSQL (متوافقة مع Supabase)
--  تصميم متعدد المستأجرين (Multi-tenant): كل مكتب مراجعة = شركة (company)
--  مستقلة ببياناتها، عملائها، موظفيها، وملفاتها.
-- ============================================================================

create extension if not exists "pgcrypto";   -- من أجل gen_random_uuid()

-- دالة عامة لتحديث حقل updated_at تلقائيًا عند أي تعديل
create or replace function fn_set_updated_at()
returns trigger as $$
begin
  new.updated_at = now();
  return new;
end;
$$ language plpgsql;


-- ============================================================================
-- 1) الشركات (مكاتب المراجعة المشتركة في المنصة)
-- ============================================================================
create table companies (
    id                  uuid primary key default gen_random_uuid(),
    code                varchar(20)  not null unique,      -- رمز المكتب المستخدم عند تسجيل الدخول (مثال: ETQAN)
    name_ar             varchar(200) not null,
    name_en             varchar(200),
    logo_url            text,                               -- شعار المكتب
    letterhead_url      text,                               -- اكليشة التقارير
    license_no          varchar(50),                        -- رخصة مزاولة المهنة
    cr_number           varchar(50),                        -- السجل التجاري
    tax_number          varchar(50),                        -- الرقم الضريبي
    email               varchar(150),
    website             varchar(150),
    phone               varchar(30),
    fax                 varchar(30),
    street              text,
    city                varchar(100),
    postal_code         varchar(20),
    subscription_start  date         not null default current_date,
    subscription_end    date         not null,               -- تاريخ انتهاء الاشتراك
    is_active           boolean      not null default true,  -- تعطيل يدوي مستقل عن تاريخ الانتهاء
    created_at          timestamptz  not null default now(),
    updated_at          timestamptz  not null default now()
);
comment on table  companies is 'مكاتب المراجعة (المستأجرون) المشتركة في المنصة';
comment on column companies.subscription_end is 'بعد هذا التاريخ يُمنع كل مستخدمي المكتب من تسجيل الدخول';

create trigger trg_companies_updated_at
    before update on companies
    for each row execute function fn_set_updated_at();


-- ============================================================================
-- 2) الأدوار (سلّم الصلاحيات الثابت داخل كل مكتب)
-- ============================================================================
create table roles (
    id          smallserial primary key,
    code        varchar(30) not null unique,   -- partner, quality, review_manager, manager, senior_auditor, auditor, admin_assistant
    name_ar     varchar(60) not null,
    name_en     varchar(60),
    level       smallint    not null            -- كلما قلّ الرقم زادت الصلاحية (1 = الأعلى)
);
comment on table roles is 'سلّم الأدوار الثابت: شريك > جودة > مدير مراجعة > مدير > مراجع أول > مراجع > مساعد إداري';

insert into roles (code, name_ar, name_en, level) values
    ('partner',         'شريك',                 'Partner',                1),
    ('quality',         'فاحص جودة ارتباط',      'Engagement Quality Reviewer', 2),
    ('review_manager',  'مدير مراجعة',           'Review Manager',         3),
    ('manager',         'مدير',                  'Manager',                3),
    ('senior_auditor',  'مراجع حسابات أول',      'Senior Auditor',         4),
    ('auditor',         'مراجع حسابات',          'Auditor',                5),
    ('admin_assistant', 'مساعد إداري',           'Administrative Assistant', 6);


-- ============================================================================
-- 3) فروع المكتب
-- ============================================================================
create table branches (
    id          uuid primary key default gen_random_uuid(),
    company_id  uuid not null references companies(id) on delete cascade,
    name        varchar(150) not null,          -- مثال: الرياض — المقر الرئيسي
    city        varchar(100),
    is_main     boolean not null default false,
    created_at  timestamptz not null default now()
);
create index idx_branches_company on branches(company_id);


-- ============================================================================
-- 4) المستخدمون (موظفو مكتب المراجعة)
-- ============================================================================
create table users (
    id                  uuid primary key default gen_random_uuid(),
    company_id          uuid not null references companies(id) on delete cascade,
    branch_id           uuid references branches(id) on delete set null,
    role_id             smallint not null references roles(id),
    first_name_ar       varchar(80) not null,
    last_name_ar        varchar(80) not null,
    first_name_en       varchar(80),
    last_name_en        varchar(80),
    gender              varchar(10) check (gender in ('male','female')),
    phone               varchar(30),
    job_title_ar        varchar(120),
    job_title_en        varchar(120),
    employment_type     varchar(30),             -- دوام كامل / جزئي / عن بعد
    is_sales_agent      boolean not null default false,   -- مندوب مبيعات؟ (نعم/لا)
    username            varchar(60) not null,
    email               varchar(150),
    password_hash       text not null,
    is_active           boolean not null default true,
    last_login_at       timestamptz,
    created_at          timestamptz not null default now(),
    updated_at          timestamptz not null default now(),
    unique (company_id, username)                -- اسم المستخدم فريد داخل نفس المكتب فقط
);
create index idx_users_company on users(company_id);
create index idx_users_role    on users(role_id);

create trigger trg_users_updated_at
    before update on users
    for each row execute function fn_set_updated_at();


-- ============================================================================
-- 5) القوائم المرجعية القابلة للتوسعة (مناطق / أنواع عملاء / قطاعات)
--    company_id = NULL  تعني قيمة افتراضية عامة تظهر لكل المكاتب
-- ============================================================================
create table regions (
    id          uuid primary key default gen_random_uuid(),
    company_id  uuid references companies(id) on delete cascade,
    name        varchar(100) not null
);

create table client_types (
    id          uuid primary key default gen_random_uuid(),
    company_id  uuid references companies(id) on delete cascade,
    name        varchar(100) not null
);

create table sectors (
    id          uuid primary key default gen_random_uuid(),
    company_id  uuid references companies(id) on delete cascade,
    name        varchar(100) not null
);

-- تعبئة مناطق المملكة كقيم افتراضية عامة (company_id = NULL)
insert into regions (company_id, name) values
    (null,'الرياض'),(null,'مكة المكرمة'),(null,'المدينة المنورة'),(null,'المنطقة الشرقية'),
    (null,'عسير'),(null,'تبوك'),(null,'حائل'),(null,'القصيم'),(null,'جازان'),
    (null,'نجران'),(null,'الباحة'),(null,'الجوف'),(null,'الحدود الشمالية');

insert into client_types (company_id, name) values
    (null,'شركة ذات مسؤولية محدودة'),(null,'مؤسسة فردية'),(null,'شركة مساهمة مقفلة'),
    (null,'شركة مساهمة عامة'),(null,'شركة تضامن'),(null,'جمعية أهلية غير ربحية');

insert into sectors (company_id, name) values
    (null,'تجارة تجزئة وجملة'),(null,'صناعة وتصنيع'),(null,'مقاولات وإنشاءات'),(null,'عقارات'),
    (null,'خدمات مالية واستثمار'),(null,'تقنية المعلومات'),(null,'رعاية صحية'),
    (null,'تعليم'),(null,'مواد غذائية'),(null,'نقل ولوجستيات');


-- ============================================================================
-- 6) العملاء
-- ============================================================================
create table clients (
    id                  uuid primary key default gen_random_uuid(),
    company_id          uuid not null references companies(id) on delete cascade,
    name                varchar(200) not null,
    client_code         varchar(30),                 -- يُنشأ تلقائيًا (CL-1042)
    custom_code         varchar(30),                 -- رمز مخصص من المكتب
    email               varchar(150),
    website             varchar(150),
    phone               varchar(30),
    phone_ext           varchar(10),
    fax                 varchar(30),
    street              text,
    additional_address  text,
    building_no         varchar(20),
    additional_no       varchar(20),
    city                varchar(100),
    district            varchar(100),
    po_box              varchar(30),
    postal_code         varchar(20),
    cr_number           varchar(50),
    registration_date   date,
    has_tax             boolean default false,
    tax_number          varchar(50),
    client_type_id      uuid references client_types(id),
    sector_id           uuid references sectors(id),
    region_id           uuid references regions(id),
    office_branch_id    uuid references branches(id),   -- موقع المكتب المسؤول عن العميل
    review_manager_id   uuid references users(id),      -- مدير المراجعة المسؤول
    status              varchar(20) not null default 'active',  -- active / paused / archived
    created_by          uuid references users(id),
    created_at          timestamptz not null default now(),
    updated_at          timestamptz not null default now()
);
create index idx_clients_company on clients(company_id);
create index idx_clients_status  on clients(status);

create trigger trg_clients_updated_at
    before update on clients
    for each row execute function fn_set_updated_at();

-- فروع العميل نفسه (وليس فروع المكتب)
create table client_branches (
    id          uuid primary key default gen_random_uuid(),
    client_id   uuid not null references clients(id) on delete cascade,
    name        varchar(150) not null,
    city        varchar(100)
);

-- موظفو العميل (جهات الاتصال لديه — وليسوا موظفي مكتب المراجعة)
create table client_employees (
    id                  uuid primary key default gen_random_uuid(),
    client_id           uuid not null references clients(id) on delete cascade,
    full_name           varchar(150) not null,
    job_title           varchar(120),
    email               varchar(150),
    phone               varchar(30),
    is_primary_contact  boolean not null default false,
    created_at          timestamptz not null default now()
);
create index idx_client_employees_client on client_employees(client_id);

-- ربط العملاء بالمراجعين (علاقة متعددة لمتعددة: عميل واحد ↔ عدة مراجعين)
create table client_reviewer_assignments (
    id           uuid primary key default gen_random_uuid(),
    client_id    uuid not null references clients(id) on delete cascade,
    user_id      uuid not null references users(id)   on delete cascade,
    assigned_at  timestamptz not null default now(),
    unique (client_id, user_id)
);
create index idx_cra_client on client_reviewer_assignments(client_id);
create index idx_cra_user   on client_reviewer_assignments(user_id);


-- ============================================================================
-- 7) ملفات التدقيق (الارتباطات) لكل عميل
-- ============================================================================
create table client_files (
    id              uuid primary key default gen_random_uuid(),
    client_id       uuid not null references clients(id) on delete cascade,
    name            varchar(200) not null,          -- مثال: مراجعة سنوية 2025
    period_end      date,
    engagement_type varchar(50),                    -- البوابة: مراجعة سنوية / ربعية / زكاة وضريبة
    status          varchar(30) not null default 'in_progress',  -- in_progress / ready_for_partner / closed
    created_by      uuid references users(id),
    created_at      timestamptz not null default now()
);
create index idx_client_files_client on client_files(client_id);

-- موازين المراجعة المرفوعة (بإصدارات متعددة لكل ملف)
create table trial_balances (
    id              uuid primary key default gen_random_uuid(),
    client_file_id  uuid not null references client_files(id) on delete cascade,
    file_url        text not null,
    version         int  not null default 1,
    status          varchar(30) not null default 'pending',  -- pending / matched / unexplained_diff
    uploaded_by     uuid references users(id),
    uploaded_at     timestamptz not null default now()
);
create index idx_trial_balances_file on trial_balances(client_file_id);

-- مستندات عامة (عقود تأسيس، مستخلصات بنكية، إلخ) قد تتبع عميلًا أو ملف تدقيق محدد
create table documents (
    id              uuid primary key default gen_random_uuid(),
    company_id      uuid not null references companies(id) on delete cascade,
    client_id       uuid references clients(id) on delete cascade,
    client_file_id  uuid references client_files(id) on delete cascade,
    category        varchar(50),
    name            varchar(200) not null,
    file_url        text not null,
    file_type       varchar(20),
    file_size_kb    int,
    uploaded_by     uuid references users(id),
    uploaded_at     timestamptz not null default now()
);
create index idx_documents_client on documents(client_id);


-- ============================================================================
-- 8) تهيئة النظام: دليل الحسابات / السياسات / أوراق العمل / تقرير المراجع
-- ============================================================================
create table chart_of_accounts (
    id              uuid primary key default gen_random_uuid(),
    company_id      uuid not null references companies(id) on delete cascade,
    code            varchar(20) not null,
    name_ar         varchar(150) not null,
    name_en         varchar(150),
    language        varchar(20) not null default 'both',   -- ar / en / both
    level           smallint not null check (level between 1 and 4),
    parent_id       uuid references chart_of_accounts(id),
    deposit_account_id uuid references chart_of_accounts(id),  -- حساب بند الإيداع
    statement_code  varchar(30),                              -- كود القوائم (يُحدَّد لاحقًا)
    is_active       boolean not null default true,
    created_at      timestamptz not null default now(),
    unique (company_id, code)
);
create index idx_coa_company on chart_of_accounts(company_id);
create index idx_coa_parent  on chart_of_accounts(parent_id);

create table policies (
    id                 uuid primary key default gen_random_uuid(),
    company_id         uuid not null references companies(id) on delete cascade,
    title              varchar(200) not null,
    department         varchar(100),
    last_reviewed_date date,
    status             varchar(20) not null default 'active',  -- active / updating
    file_url           text,
    created_at         timestamptz not null default now()
);

-- مجموعات أوراق العمل (المستوى الأول) — قد ترتبط ببند من دليل الحسابات مستوى 2
-- كل مجموعة تتبع مكتبًا واحدًا فقط (company_id) — لا مشاركة بين المكاتب
create table wp_groups (
    id              uuid primary key default gen_random_uuid(),
    company_id      uuid not null references companies(id) on delete cascade,
    code            varchar(20) not null,
    name            varchar(200) not null,
    coa_account_id  uuid references chart_of_accounts(id),   -- ربط اختياري ببند من دليل حسابات نفس المكتب (مستوى 2)
    visibility      varchar(10) not null default 'general' check (visibility in ('general','special')),
    is_active       boolean not null default true,
    created_at      timestamptz not null default now(),
    unique (company_id, code)
);
create index idx_wp_groups_company on wp_groups(company_id);

-- أوراق العمل الرئيسية داخل كل مجموعة (company_id مكرر عمدًا لتبسيط عزل البيانات RLS)
create table wp_main_items (
    id              uuid primary key default gen_random_uuid(),
    company_id      uuid not null references companies(id) on delete cascade,
    group_id        uuid not null references wp_groups(id) on delete cascade,
    code            varchar(20),
    title           varchar(200) not null,
    objective       text,          -- الهدف
    notes           text,          -- ملاحظات
    visibility      varchar(10) not null default 'general' check (visibility in ('general','special')),
    is_active       boolean not null default true,
    created_at      timestamptz not null default now()
);
create index idx_wp_main_company on wp_main_items(company_id);
create index idx_wp_main_group   on wp_main_items(group_id);

-- البنود الفرعية (الأسئلة/الحقول) داخل كل ورقة عمل رئيسية (company_id مكرر لنفس السبب)
create table wp_sub_items (
    id              uuid primary key default gen_random_uuid(),
    company_id      uuid not null references companies(id) on delete cascade,
    main_item_id    uuid not null references wp_main_items(id) on delete cascade,
    label           varchar(300) not null,
    item_type       varchar(20) not null check (item_type in ('qa','qa_attach','yesno','list','multi')),
    -- qa = سؤال وإجابة | qa_attach = إجابة مع مرفقات | yesno = نعم/لا
    -- list = قائمة اختيارات محددة + تعليق | multi = خيارات متعددة يتم تفعيلها
    options         jsonb,          -- خيارات القائمة أو الاختيارات المتعددة (list / multi فقط)
    requires_attachment boolean not null default false,   -- لنوع qa_attach
    show_comment_field  boolean not null default true,    -- لنوع list
    visibility      varchar(10) not null default 'general' check (visibility in ('general','special')),
    sort_order      int not null default 0,
    is_active       boolean not null default true,
    created_at      timestamptz not null default now()
);
create index idx_wp_sub_company on wp_sub_items(company_id);
create index idx_wp_sub_main    on wp_sub_items(main_item_id);

-- دالة تتحقق تلقائيًا أن group_id / main_item_id تابعان لنفس company_id (تمنع خلط بيانات مكتب بآخر)
create or replace function fn_check_wp_company_consistency()
returns trigger as $$
begin
    if TG_TABLE_NAME = 'wp_main_items' then
        if not exists (select 1 from wp_groups g where g.id = new.group_id and g.company_id = new.company_id) then
            raise exception 'المجموعة المحددة لا تتبع نفس مكتب هذه الورقة الرئيسية';
        end if;
    elsif TG_TABLE_NAME = 'wp_sub_items' then
        if not exists (select 1 from wp_main_items m where m.id = new.main_item_id and m.company_id = new.company_id) then
            raise exception 'الورقة الرئيسية المحددة لا تتبع نفس مكتب هذا البند الفرعي';
        end if;
    end if;
    return new;
end;
$$ language plpgsql;

create trigger trg_wp_main_company_check
    before insert or update on wp_main_items
    for each row execute function fn_check_wp_company_consistency();

create trigger trg_wp_sub_company_check
    before insert or update on wp_sub_items
    for each row execute function fn_check_wp_company_consistency();

-- استهداف الظهور "الخاص" (نوع عميل / قطاع) — يُستخدم مع wp_groups أو wp_main_items أو wp_sub_items
create table wp_visibility_targets (
    id              uuid primary key default gen_random_uuid(),
    entity_type     varchar(10) not null check (entity_type in ('group','main','sub')),
    entity_id       uuid not null,     -- يشير إلى wp_groups.id أو wp_main_items.id أو wp_sub_items.id
    client_type_id  uuid references client_types(id),
    sector_id       uuid references sectors(id)
);
create index idx_wp_vis_entity on wp_visibility_targets(entity_type, entity_id);
comment on table wp_visibility_targets is
  'عند visibility = special تُحدَّد هنا أنواع/قطاعات العملاء التي يظهر لها البند؛ إن لم توجد صفوف تطابق ملف عميل معيّن فلن يظهر له إلا إن كان عامًا';

-- بنود ميزان المراجعة المرفوعة (تفصيل كل إصدار مرفوع في trial_balances)
create table trial_balance_lines (
    id                  uuid primary key default gen_random_uuid(),
    trial_balance_id    uuid not null references trial_balances(id) on delete cascade,
    account_code        varchar(20) not null,        -- كما ورد في ملف الإكسل
    account_name        varchar(200),
    coa_account_id       uuid references chart_of_accounts(id),  -- الحساب المطابق تلقائيًا من دليل حسابات نفس المكتب
    opening_balance      numeric(16,2) not null default 0,   -- رصيد أول الفترة
    debit_movement       numeric(16,2) not null default 0,   -- مدين الحركة
    credit_movement      numeric(16,2) not null default 0,   -- دائن الحركة
    closing_balance      numeric(16,2) not null default 0,   -- رصيد آخر الفترة
    created_at           timestamptz not null default now()
);
create index idx_tbl_trial_balance on trial_balance_lines(trial_balance_id);
create index idx_tbl_coa_account   on trial_balance_lines(coa_account_id);

-- أوراق العمل الفعلية "المُدرجة" داخل ملف تدقيق عميل معيّن (نسخة عمل خاصة بهذا الملف، وليست القالب العام)
create table client_file_working_papers (
    id                uuid primary key default gen_random_uuid(),
    client_file_id    uuid not null references client_files(id) on delete cascade,
    wp_main_item_id   uuid not null references wp_main_items(id) on delete cascade,
    include_reason    varchar(20) not null check (include_reason in ('matched_tb','always','manual')),
    -- matched_tb = ورقة عمل مرتبطة بدليل الحسابات وتطابقت مع حساب في الميزان
    -- always     = ورقة عمل غير مرتبطة بدليل الحسابات (تظهر دائمًا بعد اجتياز شرط الظهور)
    -- manual     = أُضيفت يدويًا لهذا الملف بمعزل عن آلية المطابقة
    is_included       boolean not null default true,   -- يُصبح false إن لم تعد مطابقة بعد "تحديث" لاحق، دون فقدان الإجابات المدخلة
    status            varchar(20) not null default 'not_started' check (status in ('not_started','in_progress','completed')),
    created_at        timestamptz not null default now(),
    updated_at        timestamptz not null default now(),
    unique (client_file_id, wp_main_item_id)
);
create index idx_cfwp_file on client_file_working_papers(client_file_id);

create trigger trg_cfwp_updated_at
    before update on client_file_working_papers
    for each row execute function fn_set_updated_at();

-- إجابات البنود الفرعية داخل ملف تدقيق عميل معيّن
create table client_file_wp_answers (
    id                uuid primary key default gen_random_uuid(),
    client_file_id    uuid not null references client_files(id) on delete cascade,
    wp_sub_item_id    uuid not null references wp_sub_items(id) on delete cascade,
    answer_value      jsonb,     -- نص الإجابة / نعم-لا / الخيار المحدد / الخيارات المفعّلة
    comment           text,
    attachment_url    text,
    answered_by       uuid references users(id),
    answered_at       timestamptz not null default now(),
    unique (client_file_id, wp_sub_item_id)
);
create index idx_cfwa_file on client_file_wp_answers(client_file_id);

-- ============================================================================
-- 8ج) دالة "تحديث أوراق العمل" — جوهر الربط بين الميزان ودليل الحسابات وأوراق العمل
-- ============================================================================
-- الفكرة:
--   1) نجمع الحسابات التي ظهرت في آخر ميزان مراجعة مرفوع لهذا الملف.
--   2) لكل حساب، نصعد سلسلة الآباء في دليل الحسابات حتى نجمع كل الأكواد في مساره
--      (بما فيها المستوى الثالث تحديدًا، لأن مجموعات أوراق العمل غالبًا ترتبط بهذا المستوى).
--   3) أي "مجموعة" أوراق عمل مرتبطة بحساب من دليل الحسابات (coa_account_id) تندرج
--      فقط إذا كان ذلك الحساب ضمن مسار أحد حسابات الميزان.
--   4) أي "مجموعة" غير مرتبطة بدليل الحسابات (coa_account_id IS NULL) تندرج دائمًا.
--   5) من كل مجموعة مؤهلة، نأخذ فقط الأوراق الرئيسية (وبنودها الفرعية لاحقًا في الواجهة)
--      التي يسمح "ظهورها" لهذا العميل تحديدًا: إما عامة (تظهر للجميع)، أو خاصة ويطابق
--      نوع العميل و/أو قطاعه أحد صفوف wp_visibility_targets الخاصة بها.
--   6) نُدرج النتيجة في client_file_working_papers دون حذف أي إجابات سابقة؛
--      ما لم يعد مطابقًا يُعلَّم is_included = false بدل حذفه.
create or replace function fn_refresh_client_file_working_papers(p_client_file_id uuid)
returns table(wp_main_item_id uuid, include_reason varchar) as $$
declare
    v_client_id        uuid;
    v_client_type_id    uuid;
    v_sector_id         uuid;
    v_latest_tb_id      uuid;
begin
    select client_id into v_client_id from client_files where id = p_client_file_id;
    select client_type_id, sector_id into v_client_type_id, v_sector_id from clients where id = v_client_id;

    -- آخر ميزان مراجعة مرفوع لهذا الملف
    select id into v_latest_tb_id
      from trial_balances
     where client_file_id = p_client_file_id
     order by version desc
     limit 1;

    -- مسار كل حسابات الميزان صعودًا (تشمل الحساب نفسه وكل آبائه حتى المستوى 1)
    with recursive tb_accounts as (
        select distinct coa_account_id as account_id
          from trial_balance_lines
         where trial_balance_id = v_latest_tb_id
           and coa_account_id is not null
    ),
    account_ancestors as (
        select account_id, account_id as ancestor_id from tb_accounts
        union all
        select aa.account_id, coa.parent_id
          from account_ancestors aa
          join chart_of_accounts coa on coa.id = aa.ancestor_id
         where coa.parent_id is not null
    ),
    matched_groups as (
        -- مجموعات مرتبطة بدليل الحسابات وتطابق أحد حسابات/آباء حسابات الميزان
        select g.id as group_id, 'matched_tb'::varchar as reason
          from wp_groups g
         where g.coa_account_id is not null
           and exists (select 1 from account_ancestors aa where aa.ancestor_id = g.coa_account_id)
        union
        -- مجموعات غير مرتبطة بدليل الحسابات: تظهر دائمًا
        select g.id, 'always'::varchar
          from wp_groups g
         where g.coa_account_id is null
    ),
    eligible_mains as (
        select m.id as main_id, mg.reason
          from wp_main_items m
          join matched_groups mg on mg.group_id = m.group_id
         where m.is_active
           and (
                m.visibility = 'general'
                or exists (
                    select 1 from wp_visibility_targets t
                     where t.entity_type = 'main' and t.entity_id = m.id
                       and (t.client_type_id is null or t.client_type_id = v_client_type_id)
                       and (t.sector_id      is null or t.sector_id      = v_sector_id)
                )
           )
           and (
                -- المجموعة نفسها لو خاصة، لازم تطابق أيضًا
                (select g2.visibility from wp_groups g2 where g2.id = (select group_id from wp_main_items where id = m.id)) = 'general'
                or exists (
                    select 1 from wp_visibility_targets t2
                     where t2.entity_type = 'group' and t2.entity_id = (select group_id from wp_main_items where id = m.id)
                       and (t2.client_type_id is null or t2.client_type_id = v_client_type_id)
                       and (t2.sector_id      is null or t2.sector_id      = v_sector_id)
                )
           )
    )
    insert into client_file_working_papers (client_file_id, wp_main_item_id, include_reason, is_included)
    select p_client_file_id, main_id, reason, true
      from eligible_mains
    on conflict (client_file_id, wp_main_item_id)
    do update set is_included = true, include_reason = excluded.include_reason, updated_at = now();

    -- أي ورقة كانت مُدرجة سابقًا ولم تعد ضمن النتيجة الحالية: تُعطَّل دون حذف إجاباتها
    update client_file_working_papers cfwp
       set is_included = false, updated_at = now()
     where cfwp.client_file_id = p_client_file_id
       and cfwp.wp_main_item_id not in (
            select m.id
              from wp_main_items m
              join wp_groups g on g.id = m.group_id
             where (g.coa_account_id is null)
                or exists (
                    with recursive tb_accounts2 as (
                        select distinct coa_account_id as account_id
                          from trial_balance_lines
                         where trial_balance_id = v_latest_tb_id and coa_account_id is not null
                    ),
                    account_ancestors2 as (
                        select account_id, account_id as ancestor_id from tb_accounts2
                        union all
                        select a2.account_id, coa.parent_id
                          from account_ancestors2 a2
                          join chart_of_accounts coa on coa.id = a2.ancestor_id
                         where coa.parent_id is not null
                    )
                    select 1 from account_ancestors2 aa2 where aa2.ancestor_id = g.coa_account_id
                )
       );

    return query
        select cfwp.wp_main_item_id, cfwp.include_reason
          from client_file_working_papers cfwp
         where cfwp.client_file_id = p_client_file_id
           and cfwp.is_included = true;
end;
$$ language plpgsql;

comment on function fn_refresh_client_file_working_papers is
  'يُستدعى بزر "تحديث أوراق العمل" داخل ملف التدقيق. يطابق حسابات آخر ميزان مراجعة مرفوع بدليل الحسابات صعودًا حتى المستوى المرتبط، ويُدرج كل ورقة عمل مطابقة بالإضافة لكل ورقة غير مرتبطة بدليل الحسابات، مع تصفية حسب نوع/قطاع العميل (عام أو خاص) على مستوى المجموعة والورقة الرئيسية معًا.';

-- ============================================================================
-- 8ب) أمان على مستوى الصف (RLS) لجداول دليل الحسابات وأوراق العمل تحديدًا
--     كل مكتب يرى فقط دليل حساباته وأوراق عمله الخاصة — لا مشاركة إطلاقًا
-- ============================================================================
alter table chart_of_accounts enable row level security;
alter table wp_groups         enable row level security;
alter table wp_main_items     enable row level security;
alter table wp_sub_items      enable row level security;

create policy tenant_isolation_coa on chart_of_accounts
    using (company_id = (current_setting('request.jwt.claims', true)::json ->> 'company_id')::uuid);

create policy tenant_isolation_wp_groups on wp_groups
    using (company_id = (current_setting('request.jwt.claims', true)::json ->> 'company_id')::uuid);

create policy tenant_isolation_wp_main on wp_main_items
    using (company_id = (current_setting('request.jwt.claims', true)::json ->> 'company_id')::uuid);

create policy tenant_isolation_wp_sub on wp_sub_items
    using (company_id = (current_setting('request.jwt.claims', true)::json ->> 'company_id')::uuid);

-- ملاحظة: trial_balance_lines وclient_file_working_papers وclient_file_wp_answers لا تحمل company_id
-- مباشرة (تتبع client_file_id)، لذا يُطبَّق عزلها عبر join ضمنيًا بربطها بجدول clients/companies، أو
-- بإضافة عمود company_id مباشرة عليها لاحقًا بنفس نمط wp_groups إن رغبتم بتبسيط سياسات RLS عليها.

create table auditor_reports (
    id               uuid primary key default gen_random_uuid(),
    client_file_id   uuid not null references client_files(id) on delete cascade,
    opinion_type     varchar(50),           -- غير متحفظ / متحفظ / رأي سلبي / امتناع عن الرأي
    approval_stage   varchar(50) not null default 'draft',  -- draft / review_manager / quality / partner / issued
    status           varchar(30) not null default 'in_progress',
    generated_by     uuid references users(id),
    generated_at     timestamptz not null default now()
);
create index idx_auditor_reports_file on auditor_reports(client_file_id);


-- ============================================================================
-- 9) نقاط المراجعة
-- ============================================================================
create table review_points (
    id              uuid primary key default gen_random_uuid(),
    client_file_id  uuid references client_files(id) on delete cascade,
    client_id       uuid not null references clients(id) on delete cascade,
    title           varchar(200) not null,
    description     text,
    severity        varchar(10) not null check (severity in ('high','medium','low')),
    status          varchar(20) not null default 'open' check (status in ('open','in_progress','closed')),
    assigned_to     uuid references users(id),
    created_by      uuid references users(id),
    created_at      timestamptz not null default now(),
    closed_at       timestamptz
);
create index idx_review_points_client on review_points(client_id);
create index idx_review_points_status on review_points(status);


-- ============================================================================
-- 10) النماذج الجاهزة (مكتبة قوالب — عامة أو خاصة بمكتب)
-- ============================================================================
create table templates (
    id          uuid primary key default gen_random_uuid(),
    company_id  uuid references companies(id) on delete cascade,   -- NULL = قالب عام لكل المكاتب
    name        varchar(200) not null,
    category    varchar(100),
    file_url    text not null,
    file_type   varchar(20),
    created_at  timestamptz not null default now()
);


-- ============================================================================
-- 11) العروض والعقود
-- ============================================================================
create table proposals_contracts (
    id           uuid primary key default gen_random_uuid(),
    company_id   uuid not null references companies(id) on delete cascade,
    client_id    uuid references clients(id) on delete cascade,
    doc_type     varchar(20) not null check (doc_type in ('proposal','contract')),
    title        varchar(200) not null,
    amount       numeric(14,2),
    currency     varchar(10) not null default 'SAR',
    owner_id     uuid references users(id),
    status       varchar(20) not null default 'draft',  -- draft / sent / signed
    sent_date    date,
    signed_date  date,
    file_url     text,
    created_at   timestamptz not null default now()
);
create index idx_proposals_company on proposals_contracts(company_id);


-- ============================================================================
-- 12) الدردشات
-- ============================================================================
create table conversations (
    id               uuid primary key default gen_random_uuid(),
    company_id       uuid not null references companies(id) on delete cascade,
    is_group         boolean not null default false,
    title            varchar(150),
    related_client_id uuid references clients(id) on delete set null,
    created_at       timestamptz not null default now()
);

create table conversation_participants (
    id               uuid primary key default gen_random_uuid(),
    conversation_id  uuid not null references conversations(id) on delete cascade,
    user_id          uuid not null references users(id) on delete cascade,
    joined_at        timestamptz not null default now(),
    unique (conversation_id, user_id)
);

create table messages (
    id               uuid primary key default gen_random_uuid(),
    conversation_id  uuid not null references conversations(id) on delete cascade,
    sender_id        uuid not null references users(id),
    body             text not null,
    sent_at          timestamptz not null default now(),
    read_at          timestamptz
);
create index idx_messages_conversation on messages(conversation_id);


-- ============================================================================
-- 13) الإشعارات
-- ============================================================================
create table notifications (
    id          uuid primary key default gen_random_uuid(),
    user_id     uuid not null references users(id) on delete cascade,
    title       varchar(200) not null,
    body        text,
    link        varchar(200),
    is_read     boolean not null default false,
    created_at  timestamptz not null default now()
);
create index idx_notifications_user on notifications(user_id);


-- ============================================================================
-- 14) سجل تدقيق العمليات (Audit Log) — يوثّق كل تعديل مهم داخل النظام نفسه
-- ============================================================================
create table audit_log (
    id          uuid primary key default gen_random_uuid(),
    company_id  uuid not null references companies(id) on delete cascade,
    user_id     uuid references users(id),
    action      varchar(50) not null,       -- create / update / delete / login / approve ...
    entity      varchar(60) not null,       -- اسم الجدول أو الكيان
    entity_id   uuid,
    details     jsonb,
    created_at  timestamptz not null default now()
);
create index idx_audit_log_company on audit_log(company_id);


-- ============================================================================
-- 15) دوال مساعدة لمنطق تسجيل الدخول وانتهاء الاشتراك
-- ============================================================================

-- يتحقق هل مكتب معيّن (برمزه) مسموح له بتسجيل الدخول حاليًا
create or replace function fn_is_company_active(p_code varchar)
returns boolean as $$
declare
    v_end    date;
    v_active boolean;
begin
    select subscription_end, is_active
      into v_end, v_active
      from companies
     where code = p_code;

    if not found then
        return false;
    end if;

    return v_active and v_end >= current_date;
end;
$$ language plpgsql stable;

comment on function fn_is_company_active is
  'يُستخدم في شاشة تسجيل الدخول: يرفض الدخول إذا كان تاريخ انتهاء اشتراك المكتب قد مضى أو كان المكتب معطّلًا يدويًا';

-- دالة تسجيل دخول موحّدة (رمز المكتب + اسم المستخدم) تعيد بيانات المستخدم إن كان مسموحًا له
create or replace function fn_login_lookup(p_company_code varchar, p_username varchar)
returns table (
    user_id       uuid,
    company_id    uuid,
    company_name  varchar,
    role_code     varchar,
    password_hash text,
    is_user_active boolean
) as $$
begin
    if not fn_is_company_active(p_company_code) then
        return;  -- لا نتائج = رفض الدخول بسبب انتهاء الاشتراك أو تعطيل المكتب
    end if;

    return query
    select u.id, c.id, c.name_ar, r.code, u.password_hash, u.is_active
      from users u
      join companies c on c.id = u.company_id
      join roles     r on r.id = u.role_id
     where c.code = p_company_code
       and u.username = p_username;
end;
$$ language plpgsql stable;


-- ============================================================================
-- 16) أمان على مستوى الصف (Row Level Security) — مبدئي، جاهز للتفعيل في Supabase
--     الفكرة: كل مستخدم يرى فقط بيانات مكتبه (company_id) عبر JWT claim مخصص
-- ============================================================================
-- مثال تفعيل (يُطبَّق على بقية الجداول متعددة المستأجرين بنفس النمط):
--
-- alter table clients enable row level security;
--
-- create policy tenant_isolation_clients on clients
--     using (company_id = (current_setting('request.jwt.claims', true)::json ->> 'company_id')::uuid);
--
-- كرّر نفس النمط على: users, branches, client_files, review_points,
-- proposals_contracts, documents, conversations... إلخ.

-- ============================================================================
-- نهاية الملف
-- ============================================================================
