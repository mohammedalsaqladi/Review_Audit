// خادم بسيط (Node.js / Express) يخدم واجهة "تمام" الثابتة
// ويحقن إعدادات Supabase من متغيرات البيئة عند التشغيل — بدل كتابتها داخل الكود مباشرة.

const express = require('express');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// 1) يخدم كل الملفات الثابتة (index.html, صور, إلخ) من مجلد public
app.use(express.static(path.join(__dirname, 'public')));

// 2) نقطة نهاية تُنشئ ملف إعدادات JS من متغيرات البيئة الحقيقية على رندر
//    الواجهة تجلب هذا الملف عند التحميل بدل ما تحمل القيم مكتوبة داخل index.html
app.get('/config.js', (req, res) => {
  res.type('application/javascript');
  res.send(`
    window.APP_CONFIG = {
      SUPABASE_URL: ${JSON.stringify(process.env.SUPABASE_URL || '')},
      SUPABASE_ANON_KEY: ${JSON.stringify(process.env.SUPABASE_ANON_KEY || '')},
      COMPANY_ID: ${JSON.stringify(process.env.COMPANY_ID || '')}
    };
  `);
});

// 3) فحص سريع للتأكد إن السيرفر شغّال (يفيد أثناء الإعداد على رندر)
app.get('/healthz', (req, res) => res.status(200).send('ok'));

// 4) أي مسار آخر يرجّع نفس الواجهة (صفحة واحدة SPA)
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`تمام يعمل الآن على المنفذ ${PORT}`);
});
