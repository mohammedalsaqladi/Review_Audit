-- ============================================================================
--  تعديلات على قاعدة بيانات موجودة مسبقًا (نفّذها في SQL Editor بـ Supabase)
--  لا تحتاج إعادة تنفيذ schema.sql بالكامل — فقط هذه الأسطر
-- ============================================================================

-- 1) إصلاح خطأ "null value in column file_url" عند حفظ ميزان المراجعة يدويًا
alter table trial_balances alter column file_url drop not null;

-- 2) فريق المراجعة: عرض وتعديل المراجعين المرتبطين بكل عميل من ملفه الشخصي
--    الجدول client_reviewer_assignments موجود مسبقًا في schema.sql؛ لا حاجة لإنشائه
--    من جديد إن كنت نفّذت الملف الأصلي بالكامل. إن لم يكن موجودًا، نفّذ:
create table if not exists client_reviewer_assignments (
    id           uuid primary key default gen_random_uuid(),
    client_id    uuid not null references clients(id) on delete cascade,
    user_id      uuid not null references users(id)   on delete cascade,
    assigned_at  timestamptz not null default now(),
    unique (client_id, user_id)
);
create index if not exists idx_cra_client on client_reviewer_assignments(client_id);
create index if not exists idx_cra_user   on client_reviewer_assignments(user_id);
