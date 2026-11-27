#!/bin/bash

# سكريبت لرفع المشروع على GitHub Private Repository
# Script to push project to GitHub Private Repository

if [[ $# -ne 0 ]]; then
    if [[ $# -ne 2 || $1 != --prepare-for ]]; then
        echo "Use PUSH_TO_GITHUB.sh or PUSH_TO_GITHUB.sh --prepare-for <branch ref>." >&2
        exit 1
    fi
    # Keep confirmation and Git output visible while returning only the commit on stdout.
    exec 3>&1 1>&2
fi

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
export GIT_NO_REPLACE_OBJECTS=1

current_commit() {
    git rev-parse --verify --quiet 'HEAD^{commit}' || [[ $? -eq 1 ]]
}

if ! reviewed_ref=$(git symbolic-ref --quiet HEAD); then
    echo "Check out a local branch before preparing the first push." >&2
    exit 1
fi
if [[ $# -eq 2 && $reviewed_ref != "$2" ]]; then
    echo "The selected branch changed. Run this setup again." >&2
    exit 1
fi
reviewed_commit=$(current_commit) || exit 1

merge_head=$(git rev-parse --git-path MERGE_HEAD) || exit 1
if [[ -e $merge_head ]]; then
    echo "Finish or abort the pending merge before preparing the first push." >&2
    exit 1
fi
if [[ -n $reviewed_commit ]]; then
    node scripts/check-distribution.mjs history "$reviewed_commit" || exit 1
fi

# إضافة جميع الملفات
echo "📦 إضافة الملفات..."
echo "📦 Adding files..."
node scripts/check-distribution.mjs stage || exit 1
reviewed_tree=$(git write-tree) || exit 1

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

if ! current_ref=$(git symbolic-ref --quiet HEAD) ||
   ! confirmed_commit=$(current_commit) ||
   [[ $current_ref != "$reviewed_ref" || $confirmed_commit != "$reviewed_commit" ]]; then
    echo "The selected branch or commit changed during confirmation. Run this setup again." >&2
    exit 1
fi
node scripts/check-distribution.mjs index || exit 1
confirmed_tree=$(git write-tree) || exit 1
if [[ $confirmed_tree != "$reviewed_tree" ]]; then
    echo "The staged files changed during confirmation. Run this setup again." >&2
    exit 1
fi

if git diff --cached --quiet --; then
    if [[ -z $reviewed_commit ]]; then
        echo "❌ لا يوجد التزام حالي أو تغييرات جاهزة للالتزام." >&2
        echo "❌ No existing commit or staged changes to prepare." >&2
        exit 1
    fi
    prepared_commit=$reviewed_commit
    echo "✅ لا توجد تغييرات جاهزة للالتزام. الالتزام الحالي جاهز."
    echo "✅ No staged changes. The existing commit is ready."
else
    diff_status=$?
    if [[ $diff_status -ne 1 ]]; then
        exit "$diff_status"
    fi

    echo "💾 عمل commit..."
    echo "💾 Creating commit..."
    git -c user.useConfigOnly=true commit -m "Initial commit: Gmail Account Creator with GPM Login

- Migrated from GoLogin to GPM Login
- Added realistic Android User-Agent generation
- Improved proxy handling and validation
- Added comprehensive error handling" || exit 1

    prepared_commit=$(git rev-parse --verify "${reviewed_ref}^{commit}") || exit 1
    prepared_tree=$(git rev-parse --verify "${prepared_commit}^{tree}") || exit 1
    prepared_parents=$(git show --no-patch --no-notes --no-show-signature --format=%P "$prepared_commit") || exit 1
    if [[ $prepared_tree != "$reviewed_tree" || $prepared_parents != "$reviewed_commit" ]]; then
        echo "The resulting commit differs from the reviewed tree or parent. Run this setup again." >&2
        exit 1
    fi

    node scripts/check-distribution.mjs history "$prepared_commit" || exit 1
    echo ""
    echo "✅ تم عمل commit بنجاح!"
    echo "✅ Commit created successfully!"
fi

if ! current_ref=$(git symbolic-ref --quiet HEAD) ||
   ! prepared_head=$(current_commit) ||
   [[ $current_ref != "$reviewed_ref" || $prepared_head != "$prepared_commit" ]]; then
    echo "The prepared branch or commit changed. Run this setup again." >&2
    exit 1
fi
if [[ $# -eq 2 ]]; then
    printf '%s\n' "$prepared_commit" >&3
    exit 0
fi

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
printf '   expected_origin=https://github.com/YOUR_USERNAME/REPO_NAME.git\n'
printf '   first_push_ref=%q\n   prepared_commit=%q\n' "$reviewed_ref" "$prepared_commit"
cat <<'EOF'
   if current_ref=$(git symbolic-ref --quiet HEAD) &&
      main_refs=$(git for-each-ref --format='%(refname)' refs/heads/main) &&
      { [ "$current_ref" = refs/heads/main ] || [ -z "$main_refs" ]; }; then
     { [ "$current_ref" = "$first_push_ref" ] &&
       [ "$(git rev-parse --verify --quiet 'HEAD^{commit}')" = "$prepared_commit" ] ||
       { printf '%s\n' 'The prepared branch or commit changed. Run the helper again.' >&2; false; }; } &&
     git remote add origin "$expected_origin" &&
     push_origin=$(git remote get-url --push --all origin) &&
     test "$push_origin" = "$expected_origin" &&
     { [ "$first_push_ref" = refs/heads/main ] || git branch -m -- "${first_push_ref#refs/heads/}" main; } &&
     git push --no-follow-tags origin "$prepared_commit:refs/heads/main" &&
     git branch --set-upstream-to=origin/main main
   else
     printf '%s\n' 'Check out local main or a named branch when main is available.' >&2
     false
   fi

   استخدم git@github.com:YOUR_USERNAME/REPO_NAME.git لعنوان SSH.
   For SSH, set expected_origin to git@github.com:YOUR_USERNAME/REPO_NAME.git.
EOF

