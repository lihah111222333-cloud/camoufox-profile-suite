#!/bin/bash

# سكريبت لرفع المشروع على GitHub Private Repository
# Script to push project to GitHub Private Repository

echo "🚀 إعداد المشروع للرفع على GitHub..."
echo "🚀 Setting up project for GitHub push..."

# التحقق من وجود git
if ! command -v git &> /dev/null; then
    echo "❌ Git غير مثبت. يرجى تثبيت Git أولاً."
    echo "❌ Git is not installed. Please install Git first."
    exit 1
fi

if ! command -v node &> /dev/null; then
    echo "❌ Node.js is required to check the distribution files." >&2
    exit 1
fi

repository_root=$(git rev-parse --show-toplevel) || exit 1
cd "$repository_root" || exit 1

node scripts/check-distribution.mjs history || exit 1

# إضافة جميع الملفات
echo "📦 إضافة الملفات..."
echo "📦 Adding files..."
node scripts/check-distribution.mjs stage || exit 1

# عرض حالة الملفات
echo ""
echo "📋 حالة الملفات:"
echo "📋 File status:"
git diff --cached --name-status || exit 1

echo ""
echo "⚠️  تأكد من أن الملفات الحساسة غير موجودة في القائمة أعلاه!"
echo "⚠️  Make sure sensitive files are NOT in the list above!"
echo ""
read -p "هل تريد المتابعة؟ (y/n) / Continue? (y/n): " -n 1 -r
echo ""

if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "❌ تم الإلغاء"
    echo "❌ Cancelled"
    exit 1
fi

node scripts/check-distribution.mjs index || exit 1

# عمل commit
echo "💾 عمل commit..."
echo "💾 Creating commit..."
git commit -m "Initial commit: Gmail Account Creator with GPM Login

- Migrated from GoLogin to GPM Login
- Added realistic Android User-Agent generation
- Improved proxy handling and validation
- Added comprehensive error handling" || exit 1

echo ""
echo "✅ تم عمل commit بنجاح!"
echo "✅ Commit created successfully!"
echo ""
echo "📝 الخطوات التالية:"
echo "📝 Next steps:"
echo ""
echo "1. اذهب إلى https://github.com/new"
echo "   Go to https://github.com/new"
echo ""
echo "2. أنشئ repository جديد واختر 'Private'"
echo "   Create a new repository and select 'Private'"
echo ""
echo "3. بعد إنشاء الـ repository، قم بتنفيذ:"
echo "   After creating the repository, run:"
echo ""
cat <<'EOF'
   expected_origin=https://github.com/YOUR_USERNAME/REPO_NAME.git
   git remote add origin "$expected_origin" &&
     push_origin=$(git remote get-url --push --all origin) &&
     test "$push_origin" = "$expected_origin" &&
     git branch -M main &&
     git push -u origin main

   استخدم git@github.com:YOUR_USERNAME/REPO_NAME.git لعنوان SSH.
   For SSH, set expected_origin to git@github.com:YOUR_USERNAME/REPO_NAME.git.
EOF

