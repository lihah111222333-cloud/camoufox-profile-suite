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

# Check the paths before staging and again before committing.
check_git_paths() (
    set -o pipefail
    shopt -s nocasematch
    git ls-files -z "$@" | while IFS= read -r -d '' git_path; do
        case "$git_path" in
            .env.example) ;;
            *.env|*.env.*|*.emv|*.emv.*|\
            config/proxies.txt|*/config/proxies.txt|email.txt|*/email.txt|gmlogin.txt|*/gmlogin.txt|\
            results.json|*/results.json|summary.json|*/summary.json|profiles.json|*/profiles.json|\
            camoufox-audit-report.json|logs/*|data/*|profiles/*|.gpm/*|gpm-data/*)
                printf 'Sensitive file would be included in the commit: %q\n' "$git_path" >&2
                exit 1
                ;;
        esac
    done
)

repository_root=$(git rev-parse --show-toplevel) || exit 1
cd "$repository_root" || exit 1
check_git_paths --cached --others --exclude-standard || exit 1

# إضافة جميع الملفات
echo "📦 إضافة الملفات..."
echo "📦 Adding files..."
git add . || exit 1

# عرض حالة الملفات
echo ""
echo "📋 حالة الملفات:"
echo "📋 File status:"
git status --short

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

check_git_paths --cached || exit 1

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
echo "   git remote add origin https://github.com/YOUR_USERNAME/REPO_NAME.git"
echo "   git branch -M main"
echo "   git push -u origin main"
echo ""
echo "   أو إذا كنت تستخدم SSH:"
echo "   Or if using SSH:"
echo ""
echo "   git remote add origin git@github.com:YOUR_USERNAME/REPO_NAME.git"
echo "   git branch -M main"
echo "   git push -u origin main"
echo ""

