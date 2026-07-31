// أداة صغيرة لتوليد كلمة مرور مشفّرة (bcrypt) لإدخالها يدويًا في عمود
// password_hash بجدول users على Supabase، حتى يقدر ذلك المستخدم يسجّل دخول فعليًا.
//
// الاستخدام:
//   node scripts/hash-password.js "كلمة_المرور_الحقيقية"
//
// انسخ الناتج والصقه كاملاً في عمود password_hash لصف المستخدم بجدول users.

const bcrypt = require('bcryptjs');

const password = process.argv[2];
if (!password) {
  console.log('الاستخدام: node scripts/hash-password.js "كلمة المرور"');
  process.exit(1);
}

bcrypt.hash(password, 10).then((hash) => {
  console.log('\nانسخ القيمة التالية كاملة إلى عمود password_hash:\n');
  console.log(hash);
  console.log('');
});
