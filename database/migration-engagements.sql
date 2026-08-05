-- ============================================================================
-- تمام | وحدة العروض والعقود
-- جدولان فقط كما طُلب:
--   1) engagement_config  : تهيئة العروض والعقود (المكتبة النصية ثنائية اللغة)
--   2) engagements        : العروض والعقود المُنشأة فعليًا لكل عميل
-- نفّذ هذا الملف بعد migration-2026-08-03-reports.sql
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 1) تهيئة العروض والعقود
--    company_id = NULL  ⇒ مكتبة عامة لكل المكاتب
--    doc_kind: proposal (عرض سعر) / contract (عقد ارتباط)
--    template_name: نوع العرض أو العقد (مثال: "عرض سعر مراجعة قوائم سنوية")
--    block_type يحدد شكل الفقرة عند الطباعة:
--       text       = فقرة نصية عادية
--       team_table = جدول فريق العمل (يُملأ آليًا بالمؤهلات والخبرات)
--       fee_table  = جدول الأتعاب (يُملأ آليًا من المبلغ المُدخل)
--       toc        = جدول المحتويات
--       signature  = كتلة التوقيع
-- ----------------------------------------------------------------------------
create table if not exists engagement_config (
    id              uuid primary key default gen_random_uuid(),
    company_id      uuid references companies(id) on delete cascade,
    doc_kind        varchar(20)  not null,               -- proposal / contract
    template_name   varchar(200) not null,               -- نوع العرض/العقد
    group_name      varchar(200) not null,               -- المجموعة (أولاً: المقدمة ...)
    item_name       varchar(400),                        -- اسم البند المميّز
    body_ar         text,                                -- النص بالعربي
    body_en         text,                                -- النص بالإنجليزي (اختياري)
    block_type      varchar(20)  not null default 'text',
    code            varchar(30),                         -- يُولَّد تلقائيًا
    section_order   int          not null default 100,
    selection_mode  varchar(10)  not null default 'single',  -- single / multi
    is_required     boolean      not null default false,
    is_active       boolean      not null default true,
    source_id       uuid references engagement_config(id) on delete set null,
    created_by      uuid references users(id),
    created_at      timestamptz  not null default now(),
    updated_at      timestamptz  not null default now()
);
create index if not exists idx_engcfg_company  on engagement_config(company_id);
create index if not exists idx_engcfg_filter   on engagement_config(doc_kind, template_name, group_name);

drop trigger if exists trg_engcfg_updated_at on engagement_config;
create trigger trg_engcfg_updated_at
    before update on engagement_config
    for each row execute function fn_set_updated_at();

-- كود تلقائي غير قابل للتعديل
create sequence if not exists engagement_config_code_seq start 1;
create or replace function fn_auto_code_engagement_config() returns trigger as $$
begin
  if new.code is null or new.code = '' then
    new.code := 'E' || lpad(nextval('engagement_config_code_seq')::text, 5, '0');
  end if;
  return new;
end;
$$ language plpgsql;
drop trigger if exists trg_engcfg_auto_code on engagement_config;
create trigger trg_engcfg_auto_code
    before insert on engagement_config
    for each row execute function fn_auto_code_engagement_config();

comment on table engagement_config is 'تهيئة العروض والعقود: نصوص ثنائية اللغة لكل نوع عرض/عقد';


-- ----------------------------------------------------------------------------
-- 2) العروض والعقود المُنشأة
--    دورة الحياة: عرض (draft → sent → approved/rejected)
--                 عند الموافقة يُنشأ عقد مرتبط عبر proposal_id
-- ----------------------------------------------------------------------------
create table if not exists engagements (
    id                uuid primary key default gen_random_uuid(),
    company_id        uuid not null references companies(id) on delete cascade,
    client_id         uuid not null references clients(id) on delete cascade,
    client_file_id    uuid references client_files(id) on delete set null,

    doc_kind          varchar(20)  not null,             -- proposal / contract
    template_name     varchar(200),                      -- نوع العرض/العقد المستخدم
    doc_no            varchar(40),                       -- رقم العرض/العقد

    -- العقد يشير إلى العرض الذي نشأ منه
    proposal_id       uuid references engagements(id) on delete set null,

    -- الحالة:
    --   العرض : draft (مسودة) / sent (مُرسل) / approved (تمت الموافقة) / rejected (مرفوض)
    --   العقد : draft (مسودة) / signed (موقّع)
    status            varchar(20)  not null default 'draft',

    issue_date        date,                              -- تاريخ تقديم العرض
    valid_until       date,                              -- صلاحية العرض
    period_start      date,
    period_end        date,

    amount            numeric(14,2) default 0,           -- الأتعاب قبل الضريبة
    vat_rate          numeric(5,2)  default 15,
    amount_total      numeric(14,2) default 0,           -- الإجمالي شامل الضريبة
    currency          varchar(10)  not null default 'SAR',

    entity_type_text  varchar(150),                      -- نوع الشركة (يُستبدل في النص)
    place             varchar(120),
    addressee         text,

    team              jsonb not null default '[]'::jsonb,     -- فريق العمل ومؤهلاتهم
    sections          jsonb not null default '[]'::jsonb,     -- فقرات المستند
    client_snapshot   jsonb not null default '{}'::jsonb,     -- نسخة من بيانات العميل وقت الإصدار

    signature_url     text,
    stamp_url         text,
    signed_by_name    varchar(150),                      -- اسم من وقّع من طرف العميل
    signed_by_title   varchar(150),
    signed_at         timestamptz,
    approved_at       timestamptz,
    rejected_reason   text,

    public_token      varchar(48) unique,                -- لرابط الباركود/المشاركة
    created_by        uuid references users(id),
    created_at        timestamptz not null default now(),
    updated_at        timestamptz not null default now()
);
create index if not exists idx_engagements_company  on engagements(company_id);
create index if not exists idx_engagements_client   on engagements(client_id);
create index if not exists idx_engagements_kind     on engagements(doc_kind, status);
create index if not exists idx_engagements_proposal on engagements(proposal_id);

drop trigger if exists trg_engagements_updated_at on engagements;
create trigger trg_engagements_updated_at
    before update on engagements
    for each row execute function fn_set_updated_at();

comment on table engagements is 'العروض والعقود: العرض عند الموافقة يتحول لعقد مرتبط به';

-- ----------------------------------------------------------------------------
-- 3) مؤهلات وخبرات أعضاء الفريق (عمود على users — لا جدول جديد)
--    تُستخدم لتعبئة جدول فريق العمل في العرض آليًا
-- ----------------------------------------------------------------------------
-- ملاحظة: عمود job_title_ar موجود أصلًا في جدول users، فنضيف المؤهلات فقط
alter table users add column if not exists qualifications text;   -- المؤهل العلمي والخبرات المهنية


-- ============================================================================
-- 4) تعبئة مبدئية للمكتبة العامة (نموذج عرض سعر + نموذج عقد ارتباط)
-- ============================================================================
delete from engagement_config where company_id is null;

insert into engagement_config
  (company_id, doc_kind, template_name, group_name, item_name, body_ar, body_en,
   block_type, section_order, selection_mode, is_required, is_active)
values
-- ---------------- عرض سعر: مراجعة قوائم سنوية ----------------
(null,'proposal','عرض سعر مراجعة قوائم سنوية','أولاً: المقدمة','تعريف بالعميل',
 'شركة #العميل# هي #نوع الشركة# مسجلة في المملكة العربية السعودية بموجب سجل تجاري رقم (#السجل التجاري#). وترغب الشركة في مراجعة القوائم المالية للسنة المنتهية في #تاريخ أخرالفترة#.',
 null,'text',10,'single',true,true),

(null,'proposal','عرض سعر مراجعة قوائم سنوية','أولاً: المقدمة','تعريف بالمكتب',
 '#المكتب# هو أحد مكاتب المحاسبة والمراجعة المعتمدة في المملكة العربية السعودية، وله دراية خاصة في تقديم تلك الخدمات للشركات والمؤسسات والمشروعات المتنوعة. ويسعدنا تقديم خدماتنا لشركتكم لمراجعة القوائم المالية للسنة المنتهية في #تاريخ أخرالفترة#، كما نؤكد لكم التزامنا بتطوير خطة عمل خاصة لاحتياجات الشركة تتفق مع معايير المراجعة الدولية المعتمدة في المملكة.',
 null,'text',11,'multi',false,true),

(null,'proposal','عرض سعر مراجعة قوائم سنوية','ثانياً: خدمات مراجعة الحسابات','الأهداف الأساسية للمراجعة',
 'إن الهدف الأساسي لـ #المكتب# من فحص القوائم المالية للشركة هو إبداء رأي محايد من خلال مراجعتنا وفقاً للمعايير الدولية للمراجعة المعتمدة في المملكة العربية السعودية.',
 null,'text',20,'single',true,true),

(null,'proposal','عرض سعر مراجعة قوائم سنوية','ثانياً: خدمات مراجعة الحسابات','نطاق أعمال المراجعة',
 'لكي نتمكن من أداء مراجعة فعالة سنبذل قصارى جهدنا للوصول إلى تفهم كامل لأسلوب الإدارة بالشركة. وسنقوم منذ البداية بفحص كافة البيانات المالية التي تقدمها الشركة بما يمكّننا من تحديد مناطق المراجعة الهامة، ووضع خطة فعالة للمراجعة تتضمن تحديد المجالات الهامة والتوقيت اللازم لزيارات المراجعة، وإجراء دراسة وتقييم لنظم الرقابة الداخلية بالشركة.',
 null,'text',21,'multi',false,true),

(null,'proposal','عرض سعر مراجعة قوائم سنوية','ثالثاً: أسلوب تقديم الخدمات المهنية','أسلوب تقديم الخدمة',
 'سوف نعمل على تقديم خدماتنا المهنية للشركة بصورة جدية مستمرة على مدار العام، إذ نعتقد أن تواجدنا مع الشركة بصفة مستمرة سوف يجعلنا نتفهم بصورة دقيقة طبيعة نشاطها ومتطلباتها.',
 null,'text',30,'single',true,true),

(null,'proposal','عرض سعر مراجعة قوائم سنوية','رابعاً: فريق العمل','تمهيد فريق العمل',
 'سوف يقوم بتنفيذ عملية المراجعة فريق متخصص بالإضافة إلى اشتراك مدير التدقيق بالمكتب والمدير العام، ويتكون الفريق من:',
 null,'text',40,'single',true,true),

(null,'proposal','عرض سعر مراجعة قوائم سنوية','رابعاً: فريق العمل','جدول فريق العمل',
 null,null,'team_table',41,'single',true,true),

(null,'proposal','عرض سعر مراجعة قوائم سنوية','خامساً: أسلوب أداء المراجعة','أسلوب الأداء',
 'سوف يقوم فريق المراجعة بأداء عملية المراجعة بأسلوب المراجعة النهائية، وتبدأ الزيارة بعد تاريخ التعيين بغرض القيام بالإشراف على أعمال الجرد ودراسة نظم الرقابة الداخلية، ثم تُستكمل الإجراءات حتى إصدار التقرير.',
 null,'text',50,'single',true,true),

(null,'proposal','عرض سعر مراجعة قوائم سنوية','سادساً: الأتعاب المقدرة','تمهيد الأتعاب',
 'يتبع المكتب في تقديره للأتعاب أن يتم ذلك من واقع الوقت اللازم لتنفيذ مهام المراجعة، وتُحسب الأتعاب على أساس عدد ساعات العمل المقدرة لكل فرد من أفراد الفريق. وفي ضوء حرصنا على أن تكون أتعابنا مناسبة، فقد قدّرنا الأتعاب على النحو التالي:',
 null,'text',60,'single',true,true),

(null,'proposal','عرض سعر مراجعة قوائم سنوية','سادساً: الأتعاب المقدرة','جدول الأتعاب',
 null,null,'fee_table',61,'single',true,true),

-- ---------------- عقد ارتباط: مراجعة قوائم مالية ----------------
(null,'contract','عقد ارتباط مراجعة قوائم مالية','أغراض ونطاق المراجعة','الطلب ونطاق العمل',
 'لقد طلبتم منا القيام بمراجعة القوائم المالية لـ #العميل# (#نوع الشركة#) للفترة المنتهية في #تاريخ أخرالفترة#، والتي تشمل قائمة المركز المالي وقائمة الربح أو الخسارة والدخل الشامل الآخر وقائمة التغيرات في حقوق الملكية وقائمة التدفقات النقدية والإيضاحات المرفقة بها.',
 'You have requested that we audit the financial statements of #العميل#, which comprise the statement of financial position as at #تاريخ أخرالفترة#, and the statement of profit or loss and other comprehensive income, statement of changes in equity and statement of cash flows for the period then ended, and notes to the financial statements.',
 'text',10,'single',true,true),

(null,'contract','عقد ارتباط مراجعة قوائم مالية','مسؤوليات وحدود المراجعة','معايير المراجعة',
 'سنقوم بإجراء مراجعتنا وفقاً للمعايير الدولية للمراجعة المعتمدة في المملكة العربية السعودية. وتتطلب تلك المعايير أن نلتزم بالمتطلبات الأخلاقية وأن نخطط وننفذ المراجعة للحصول على تأكيد معقول بأن القوائم المالية خالية من التحريف الجوهري.',
 'We will conduct our audit in accordance with International Auditing Standards endorsed in the Kingdom of Saudi Arabia. Those standards require that we comply with ethical requirements and plan and perform the audit to obtain reasonable assurance about whether the financial statements are free from material misstatement.',
 'text',20,'single',true,true),

(null,'contract','عقد ارتباط مراجعة قوائم مالية','مسؤوليات وحدود المراجعة','حدود المراجعة',
 'نظراً للحدود الملازمة للمراجعة وحدود الرقابة الداخلية، فهناك خطر لا يمكن تجنبه بعدم اكتشاف بعض التحريفات الجوهرية حتى مع تخطيط المراجعة وتنفيذها بشكل سليم وفقاً للمعايير الدولية للمراجعة.',
 'Because of the inherent limitations of an audit, together with the inherent limitations of internal control, there is an unavoidable risk that some material misstatements may not be detected, even though the audit is properly planned and performed in accordance with International Auditing Standards.',
 'text',21,'multi',false,true),

(null,'contract','عقد ارتباط مراجعة قوائم مالية','مسؤوليات الإدارة والتمثيل','مسؤوليات الإدارة',
 'ستُجرى مراجعتنا على أساس أن الإدارة والمسؤولين عن الحوكمة يقرّون بمسؤوليتهم عن إعداد القوائم المالية وعرضها بشكل عادل، وعن الرقابة الداخلية التي يرونها ضرورية لإعداد قوائم مالية خالية من التحريف الجوهري، وعن تزويدنا بكافة المعلومات وإتاحة الوصول غير المقيّد للأشخاص داخل المنشأة.',
 'Our audit will be conducted on the basis that management and those charged with governance acknowledge their responsibility for the preparation and fair presentation of the financial statements, for such internal control as they determine is necessary, and for providing us with all relevant information and unrestricted access to persons within the entity.',
 'text',30,'single',true,true),

(null,'contract','عقد ارتباط مراجعة قوائم مالية','مدة الاتفاقية','مدة الاتفاقية',
 'تسري هذه الاتفاقية اعتباراً من تاريخ التوقيع عليها وتظل سارية للفترة المنتهية في #تاريخ أخرالفترة#، ما لم يتم إنهاؤها أو تعديلها كتابةً من الطرفين.',
 'This agreement shall be effective from the date of signature and shall remain in force for the period ending #تاريخ أخرالفترة#, unless terminated or amended in writing by both parties.',
 'text',40,'single',true,true),

(null,'contract','عقد ارتباط مراجعة قوائم مالية','الجدول الزمني','الجدول الزمني',
 'سنقوم بتخطيط أداء مراجعتنا وفقاً لجدول زمني يتم تحديده قبل بدء العمل بالاتفاق معكم. وإن المساعدة المقدمة من قبل موظفيكم، بما في ذلك إعداد الجداول والتحليلات المطلوبة، تساعد على إنجاز العمل في موعده.',
 'We will plan the performance of our audit in accordance with a timetable to be agreed with you before commencement. Assistance to be supplied by your personnel, including the preparation of required schedules and analyses, helps in completing the work on time.',
 'text',50,'single',true,true),

(null,'contract','عقد ارتباط مراجعة قوائم مالية','الأتعاب وإجراءات الفواتير','أساس احتساب الأتعاب',
 'تُحسب أتعابنا على أساس الوقت المنصرف والمصاريف التي نتكبدها، وقد بلغت الأتعاب المتفق عليها مبلغ #المبلغ# ريال سعودي (غير شامل ضريبة القيمة المضافة).',
 'Our fees are charged on the basis of time occupied and expenses incurred. The agreed fees amount to SAR #المبلغ# (excluding value added tax).',
 'text',60,'single',true,true),

(null,'contract','عقد ارتباط مراجعة قوائم مالية','الأتعاب وإجراءات الفواتير','جدول الأتعاب',
 null,null,'fee_table',61,'single',true,true),

(null,'contract','عقد ارتباط مراجعة قوائم مالية','الأتعاب وإجراءات الفواتير','استحقاق الفواتير',
 'جميع الفواتير تكون مستحقة الدفع خلال (30) يوماً من تاريخ استلامكم لها. وسنبلغكم فوراً بأي ظروف قد تؤثر بشكل كبير على تقديرنا الأولي للأتعاب.',
 'All invoices will be due for payment within thirty (30) days of receipt. We will notify you promptly of any circumstances we encounter that could significantly affect our initial estimate of fees.',
 'text',62,'multi',false,true),

(null,'contract','عقد ارتباط مراجعة قوائم مالية','الإقرار والتوقيع','طلب التوقيع',
 'الرجاء منكم التوقيع وإعادة النسخة المرفقة من هذا الخطاب إلينا للدلالة على موافقتكم على الترتيبات الخاصة بمراجعتنا للقوائم المالية.',
 'Please sign and return the attached copy of this letter to indicate your agreement with the arrangements for our audit of the financial statements.',
 'text',70,'single',true,true),

(null,'contract','عقد ارتباط مراجعة قوائم مالية','الإقرار والتوقيع','كتلة التوقيع',
 null,null,'signature',71,'single',true,true);
