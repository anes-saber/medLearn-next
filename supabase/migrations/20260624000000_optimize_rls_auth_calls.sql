-- Optimize RLS policies: wrap auth.jwt(), auth.uid(), and get_my_role()
-- in (SELECT ...) so they are evaluated once per query instead of per row.
-- See https://supabase.com/docs/guides/database/postgres/row-level-security#call-functions-with-select

-- ============================================================
-- 0. Fix get_my_role() itself to use (SELECT auth.jwt())
-- ============================================================
CREATE OR REPLACE FUNCTION public.get_my_role()
RETURNS TEXT
LANGUAGE sql
STABLE
SECURITY INVOKER
AS $$
  SELECT COALESCE(
    (SELECT auth.jwt()) -> 'app_metadata' ->> 'role',
    'student'
  );
$$;

-- ==================== RESOURCES ====================
DROP POLICY IF EXISTS "View published or own resources" ON public.resources;
DROP POLICY IF EXISTS "Admin/teacher can insert resources" ON public.resources;
DROP POLICY IF EXISTS "Admin/teacher can update resources" ON public.resources;
DROP POLICY IF EXISTS "Admin/teacher can delete resources" ON public.resources;

DROP POLICY IF EXISTS "View published or own resources" ON public.resources;
CREATE POLICY "View published or own resources"
  ON public.resources FOR SELECT
  USING (
    published = true
    OR COALESCE((SELECT auth.jwt()) -> 'app_metadata' ->> 'role', 'student') IN ('admin', 'teacher')
  );

DROP POLICY IF EXISTS "Admin/teacher can insert resources" ON public.resources;
CREATE POLICY "Admin/teacher can insert resources"
  ON public.resources FOR INSERT
  WITH CHECK (COALESCE((SELECT auth.jwt()) -> 'app_metadata' ->> 'role', 'student') IN ('admin', 'teacher'));

DROP POLICY IF EXISTS "Admin/teacher can update resources" ON public.resources;
CREATE POLICY "Admin/teacher can update resources"
  ON public.resources FOR UPDATE
  USING  (COALESCE((SELECT auth.jwt()) -> 'app_metadata' ->> 'role', 'student') IN ('admin', 'teacher'))
  WITH CHECK (COALESCE((SELECT auth.jwt()) -> 'app_metadata' ->> 'role', 'student') IN ('admin', 'teacher'));

DROP POLICY IF EXISTS "Admin/teacher can delete resources" ON public.resources;
CREATE POLICY "Admin/teacher can delete resources"
  ON public.resources FOR DELETE
  USING (COALESCE((SELECT auth.jwt()) -> 'app_metadata' ->> 'role', 'student') IN ('admin', 'teacher'));

-- Drop unused indexes (no queries filter by these)
DROP INDEX IF EXISTS idx_resources_created_by;
DROP INDEX IF EXISTS idx_questions_major_id;
DROP INDEX IF EXISTS idx_questions_module_id;
DROP INDEX IF EXISTS idx_questions_created_by;
DROP INDEX IF EXISTS idx_quizzes_major_id;
DROP INDEX IF EXISTS idx_quizzes_module_id;
DROP INDEX IF EXISTS idx_quizzes_created_by;
DROP INDEX IF EXISTS idx_quiz_questions_question_id;
DROP INDEX IF EXISTS idx_homeworks_major_id;
DROP INDEX IF EXISTS idx_homeworks_module_id;
DROP INDEX IF EXISTS idx_homeworks_created_by;
DROP INDEX IF EXISTS idx_quiz_attempts_quiz_id;
DROP INDEX IF EXISTS idx_quiz_attempts_user_id;
DROP INDEX IF EXISTS idx_quiz_attempts_session_id;

-- ==================== HOMEWORKS ====================
DROP POLICY IF EXISTS "Anyone can view published homeworks" ON public.homeworks;
DROP POLICY IF EXISTS "Admin/teacher can insert homeworks" ON public.homeworks;
DROP POLICY IF EXISTS "Admin/teacher can update homeworks" ON public.homeworks;
DROP POLICY IF EXISTS "Admin/teacher can delete homeworks" ON public.homeworks;

DROP POLICY IF EXISTS "Anyone can view published homeworks" ON public.homeworks;
CREATE POLICY "Anyone can view published homeworks"
  ON public.homeworks FOR SELECT
  USING (published = true OR COALESCE((SELECT auth.jwt()) -> 'app_metadata' ->> 'role', 'student') IN ('admin', 'teacher'));

DROP POLICY IF EXISTS "Admin/teacher can insert homeworks" ON public.homeworks;
CREATE POLICY "Admin/teacher can insert homeworks"
  ON public.homeworks FOR INSERT
  WITH CHECK (COALESCE((SELECT auth.jwt()) -> 'app_metadata' ->> 'role', 'student') IN ('admin', 'teacher'));

DROP POLICY IF EXISTS "Admin/teacher can update homeworks" ON public.homeworks;
CREATE POLICY "Admin/teacher can update homeworks"
  ON public.homeworks FOR UPDATE
  USING  (COALESCE((SELECT auth.jwt()) -> 'app_metadata' ->> 'role', 'student') IN ('admin', 'teacher'))
  WITH CHECK (COALESCE((SELECT auth.jwt()) -> 'app_metadata' ->> 'role', 'student') IN ('admin', 'teacher'));

DROP POLICY IF EXISTS "Admin/teacher can delete homeworks" ON public.homeworks;
CREATE POLICY "Admin/teacher can delete homeworks"
  ON public.homeworks FOR DELETE
  USING (COALESCE((SELECT auth.jwt()) -> 'app_metadata' ->> 'role', 'student') IN ('admin', 'teacher'));

-- ==================== QUIZZES ====================
DROP POLICY IF EXISTS "Anyone can view published quizzes" ON public.quizzes;
DROP POLICY IF EXISTS "Admin/teacher can insert quizzes" ON public.quizzes;
DROP POLICY IF EXISTS "Admin/teacher can update quizzes" ON public.quizzes;
DROP POLICY IF EXISTS "Admin/teacher can delete quizzes" ON public.quizzes;

DROP POLICY IF EXISTS "Anyone can view published quizzes" ON public.quizzes;
CREATE POLICY "Anyone can view published quizzes"
  ON public.quizzes FOR SELECT
  USING (published = true OR COALESCE((SELECT auth.jwt()) -> 'app_metadata' ->> 'role', 'student') IN ('admin', 'teacher'));

DROP POLICY IF EXISTS "Admin/teacher can insert quizzes" ON public.quizzes;
CREATE POLICY "Admin/teacher can insert quizzes"
  ON public.quizzes FOR INSERT
  WITH CHECK (COALESCE((SELECT auth.jwt()) -> 'app_metadata' ->> 'role', 'student') IN ('admin', 'teacher'));

DROP POLICY IF EXISTS "Admin/teacher can update quizzes" ON public.quizzes;
CREATE POLICY "Admin/teacher can update quizzes"
  ON public.quizzes FOR UPDATE
  USING  (COALESCE((SELECT auth.jwt()) -> 'app_metadata' ->> 'role', 'student') IN ('admin', 'teacher'))
  WITH CHECK (COALESCE((SELECT auth.jwt()) -> 'app_metadata' ->> 'role', 'student') IN ('admin', 'teacher'));

DROP POLICY IF EXISTS "Admin/teacher can delete quizzes" ON public.quizzes;
CREATE POLICY "Admin/teacher can delete quizzes"
  ON public.quizzes FOR DELETE
  USING (COALESCE((SELECT auth.jwt()) -> 'app_metadata' ->> 'role', 'student') IN ('admin', 'teacher'));

-- ==================== QUESTIONS ====================
DROP POLICY IF EXISTS "Anyone can view published questions" ON public.questions;
DROP POLICY IF EXISTS "Admin/teacher can insert questions" ON public.questions;
DROP POLICY IF EXISTS "Admin/teacher can update questions" ON public.questions;
DROP POLICY IF EXISTS "Admin/teacher can delete questions" ON public.questions;

DROP POLICY IF EXISTS "Anyone can view published questions" ON public.questions;
CREATE POLICY "Anyone can view published questions"
  ON public.questions FOR SELECT
  USING (published = true OR COALESCE((SELECT auth.jwt()) -> 'app_metadata' ->> 'role', 'student') IN ('admin', 'teacher'));

DROP POLICY IF EXISTS "Admin/teacher can insert questions" ON public.questions;
CREATE POLICY "Admin/teacher can insert questions"
  ON public.questions FOR INSERT
  WITH CHECK (COALESCE((SELECT auth.jwt()) -> 'app_metadata' ->> 'role', 'student') IN ('admin', 'teacher'));

DROP POLICY IF EXISTS "Admin/teacher can update questions" ON public.questions;
CREATE POLICY "Admin/teacher can update questions"
  ON public.questions FOR UPDATE
  USING  (COALESCE((SELECT auth.jwt()) -> 'app_metadata' ->> 'role', 'student') IN ('admin', 'teacher'))
  WITH CHECK (COALESCE((SELECT auth.jwt()) -> 'app_metadata' ->> 'role', 'student') IN ('admin', 'teacher'));

DROP POLICY IF EXISTS "Admin/teacher can delete questions" ON public.questions;
CREATE POLICY "Admin/teacher can delete questions"
  ON public.questions FOR DELETE
  USING (COALESCE((SELECT auth.jwt()) -> 'app_metadata' ->> 'role', 'student') IN ('admin', 'teacher'));

-- ==================== PROFILES ====================
DROP POLICY IF EXISTS "Users can view own profile" ON public.profiles;
DROP POLICY IF EXISTS "Users can read own profile" ON public.profiles;
DROP POLICY IF EXISTS "Admin/teacher can view all profiles" ON public.profiles;
DROP POLICY IF EXISTS "Admin/teacher can read all profiles" ON public.profiles;
DROP POLICY IF EXISTS "Admin/teacher can update any profile" ON public.profiles;
DROP POLICY IF EXISTS "Admin/teacher can update profiles" ON public.profiles;

DROP POLICY IF EXISTS "Users can view own profile, admin/teacher can view all" ON public.profiles;
DROP POLICY IF EXISTS "Users can view own profile, admin/teacher can view all" ON public.profiles;
CREATE POLICY "Users can view own profile, admin/teacher can view all"
  ON public.profiles FOR SELECT
  USING (
    (SELECT auth.uid()) = id
    OR (SELECT public.get_my_role()) IN ('admin', 'teacher')
  );

DROP POLICY IF EXISTS "Admin/teacher can update profiles" ON public.profiles;
CREATE POLICY "Admin/teacher can update profiles"
  ON public.profiles FOR UPDATE
  USING  (COALESCE((SELECT auth.jwt()) -> 'app_metadata' ->> 'role', 'student') IN ('admin', 'teacher'))
  WITH CHECK (COALESCE((SELECT auth.jwt()) -> 'app_metadata' ->> 'role', 'student') IN ('admin', 'teacher'));

-- ==================== MAJORS ====================
DROP POLICY IF EXISTS "Anyone can view majors" ON public.majors;
DROP POLICY IF EXISTS "Admin/teacher can insert majors" ON public.majors;
DROP POLICY IF EXISTS "Admin/teacher can update majors" ON public.majors;
DROP POLICY IF EXISTS "Admin/teacher can delete majors" ON public.majors;

DROP POLICY IF EXISTS "Anyone can view majors" ON public.majors;
CREATE POLICY "Anyone can view majors"
  ON public.majors FOR SELECT
  USING (true);

DROP POLICY IF EXISTS "Admin/teacher can insert majors" ON public.majors;
CREATE POLICY "Admin/teacher can insert majors"
  ON public.majors FOR INSERT
  WITH CHECK ((SELECT public.get_my_role()) IN ('admin', 'teacher'));

DROP POLICY IF EXISTS "Admin/teacher can update majors" ON public.majors;
CREATE POLICY "Admin/teacher can update majors"
  ON public.majors FOR UPDATE
  USING  ((SELECT public.get_my_role()) IN ('admin', 'teacher'))
  WITH CHECK ((SELECT public.get_my_role()) IN ('admin', 'teacher'));

DROP POLICY IF EXISTS "Admin/teacher can delete majors" ON public.majors;
CREATE POLICY "Admin/teacher can delete majors"
  ON public.majors FOR DELETE
  USING ((SELECT public.get_my_role()) IN ('admin', 'teacher'));

-- ==================== MODULES ====================
DROP POLICY IF EXISTS "Anyone can view modules" ON public.modules;
DROP POLICY IF EXISTS "Admin/teacher can insert modules" ON public.modules;
DROP POLICY IF EXISTS "Admin/teacher can update modules" ON public.modules;
DROP POLICY IF EXISTS "Admin/teacher can delete modules" ON public.modules;

DROP POLICY IF EXISTS "Anyone can view modules" ON public.modules;
CREATE POLICY "Anyone can view modules"
  ON public.modules FOR SELECT
  USING (true);

DROP POLICY IF EXISTS "Admin/teacher can insert modules" ON public.modules;
CREATE POLICY "Admin/teacher can insert modules"
  ON public.modules FOR INSERT
  WITH CHECK ((SELECT public.get_my_role()) IN ('admin', 'teacher'));

DROP POLICY IF EXISTS "Admin/teacher can update modules" ON public.modules;
CREATE POLICY "Admin/teacher can update modules"
  ON public.modules FOR UPDATE
  USING  ((SELECT public.get_my_role()) IN ('admin', 'teacher'))
  WITH CHECK ((SELECT public.get_my_role()) IN ('admin', 'teacher'));

DROP POLICY IF EXISTS "Admin/teacher can delete modules" ON public.modules;
CREATE POLICY "Admin/teacher can delete modules"
  ON public.modules FOR DELETE
  USING ((SELECT public.get_my_role()) IN ('admin', 'teacher'));

-- ==================== QUIZ ATTEMPTS ====================
DROP POLICY IF EXISTS "Users can view their own attempts" ON public.quiz_attempts;
DROP POLICY IF EXISTS "Teachers and admins can view all attempts" ON public.quiz_attempts;
DROP POLICY IF EXISTS "Users can insert their own attempts" ON public.quiz_attempts;
DROP POLICY IF EXISTS "Anonymous can insert attempts" ON public.quiz_attempts;
DROP POLICY IF EXISTS "Anonymous can view their attempts in current session (if any)" ON public.quiz_attempts;
DROP POLICY IF EXISTS "Users can view own quiz_attempts" ON public.quiz_attempts;
DROP POLICY IF EXISTS "Teachers and admins can view all" ON public.quiz_attempts;
DROP POLICY IF EXISTS "Users can insert own quiz_attempts" ON public.quiz_attempts;
DROP POLICY IF EXISTS "Anyone can insert anonymous quiz_attempts" ON public.quiz_attempts;
DROP POLICY IF EXISTS "Anyone can view anonymous quiz_attempts" ON public.quiz_attempts;

DROP POLICY IF EXISTS "View own attempts" ON public.quiz_attempts;
DROP POLICY IF EXISTS "Teachers and admins can view all attempts" ON public.quiz_attempts;
DROP POLICY IF EXISTS "View anonymous attempts" ON public.quiz_attempts;
DROP POLICY IF EXISTS "Insert own attempts" ON public.quiz_attempts;
DROP POLICY IF EXISTS "Insert anonymous attempts" ON public.quiz_attempts;
DROP POLICY IF EXISTS "View quiz attempts" ON public.quiz_attempts;
DROP POLICY IF EXISTS "Insert quiz attempts" ON public.quiz_attempts;

CREATE POLICY "View quiz attempts"
  ON public.quiz_attempts FOR SELECT
  USING (
    (SELECT auth.uid()) = user_id
    OR ((SELECT auth.uid()) IS NULL AND user_id IS NULL)
    OR (SELECT public.get_my_role()) IN ('teacher', 'admin')
  );

CREATE POLICY "Insert quiz attempts"
  ON public.quiz_attempts FOR INSERT
  WITH CHECK (
    (SELECT auth.uid()) = user_id
    OR ((SELECT auth.uid()) IS NULL AND user_id IS NULL)
  );

-- ==================== HOMEWORK SUBMISSIONS ====================
DROP POLICY IF EXISTS "Users see own submissions, admin/teacher see all" ON public.homework_submissions;
DROP POLICY IF EXISTS "Admin/teacher can update submissions" ON public.homework_submissions;
DROP POLICY IF EXISTS "Admin/teacher can delete submissions" ON public.homework_submissions;

DROP POLICY IF EXISTS "Users see own submissions, admin/teacher see all" ON public.homework_submissions;
CREATE POLICY "Users see own submissions, admin/teacher see all"
  ON public.homework_submissions FOR SELECT
  USING (
    user_id = (SELECT auth.uid())
    OR (SELECT public.get_my_role()) IN ('admin', 'teacher')
  );

DROP POLICY IF EXISTS "Admin/teacher can update submissions" ON public.homework_submissions;
CREATE POLICY "Admin/teacher can update submissions"
  ON public.homework_submissions FOR UPDATE
  USING  ((SELECT public.get_my_role()) IN ('admin', 'teacher'))
  WITH CHECK ((SELECT public.get_my_role()) IN ('admin', 'teacher'));

DROP POLICY IF EXISTS "Admin/teacher can delete submissions" ON public.homework_submissions;
CREATE POLICY "Admin/teacher can delete submissions"
  ON public.homework_submissions FOR DELETE
  USING ((SELECT public.get_my_role()) IN ('admin', 'teacher'));

-- ==================== QUIZ QUESTIONS ====================
DROP POLICY IF EXISTS "Anyone can view quiz_questions for published quizzes" ON public.quiz_questions;
DROP POLICY IF EXISTS "Admin/teacher can manage quiz_questions" ON public.quiz_questions;
DROP POLICY IF EXISTS "View quiz questions" ON public.quiz_questions;
DROP POLICY IF EXISTS "Admin/teacher can insert quiz questions" ON public.quiz_questions;
DROP POLICY IF EXISTS "Admin/teacher can update quiz questions" ON public.quiz_questions;
DROP POLICY IF EXISTS "Admin/teacher can delete quiz questions" ON public.quiz_questions;

CREATE POLICY "View quiz questions"
  ON public.quiz_questions FOR SELECT
  USING (
    EXISTS (
      SELECT 1 FROM public.quizzes q
      WHERE q.id = quiz_id
        AND (q.published = true OR (SELECT public.get_my_role()) IN ('admin', 'teacher'))
    )
  );

CREATE POLICY "Admin/teacher can insert quiz questions"
  ON public.quiz_questions FOR INSERT
  WITH CHECK ((SELECT public.get_my_role()) IN ('admin', 'teacher'));

CREATE POLICY "Admin/teacher can update quiz questions"
  ON public.quiz_questions FOR UPDATE
  USING  ((SELECT public.get_my_role()) IN ('admin', 'teacher'))
  WITH CHECK ((SELECT public.get_my_role()) IN ('admin', 'teacher'));

CREATE POLICY "Admin/teacher can delete quiz questions"
  ON public.quiz_questions FOR DELETE
  USING ((SELECT public.get_my_role()) IN ('admin', 'teacher'));

-- ==================== STORAGE (resources bucket) ====================
DROP POLICY IF EXISTS "Admin/teacher can upload files" ON storage.objects;
DROP POLICY IF EXISTS "Admin/teacher can update files" ON storage.objects;
DROP POLICY IF EXISTS "Admin/teacher can delete files" ON storage.objects;
DROP POLICY IF EXISTS "Admin/teacher can manage resources bucket" ON storage.objects;

CREATE POLICY "Admin/teacher can manage resources bucket"
  ON storage.objects FOR ALL
  USING  (bucket_id = 'resources' AND COALESCE((SELECT auth.jwt()) -> 'app_metadata' ->> 'role', 'student') IN ('admin', 'teacher'))
  WITH CHECK (bucket_id = 'resources' AND COALESCE((SELECT auth.jwt()) -> 'app_metadata' ->> 'role', 'student') IN ('admin', 'teacher'));

-- ============================================================
-- Create indexes on foreign key columns for JOIN/cascade perf
-- ============================================================
CREATE INDEX IF NOT EXISTS idx_modules_major_id       ON public.modules (major_id);
CREATE INDEX IF NOT EXISTS idx_questions_major_id     ON public.questions (major_id);
CREATE INDEX IF NOT EXISTS idx_questions_module_id    ON public.questions (module_id);
CREATE INDEX IF NOT EXISTS idx_questions_created_by   ON public.questions (created_by);
CREATE INDEX IF NOT EXISTS idx_quizzes_major_id       ON public.quizzes (major_id);
CREATE INDEX IF NOT EXISTS idx_quizzes_module_id      ON public.quizzes (module_id);
CREATE INDEX IF NOT EXISTS idx_quizzes_created_by     ON public.quizzes (created_by);
CREATE INDEX IF NOT EXISTS idx_quiz_questions_question_id ON public.quiz_questions (question_id);
CREATE INDEX IF NOT EXISTS idx_homeworks_major_id     ON public.homeworks (major_id);
CREATE INDEX IF NOT EXISTS idx_homeworks_module_id    ON public.homeworks (module_id);
CREATE INDEX IF NOT EXISTS idx_homeworks_created_by   ON public.homeworks (created_by);
CREATE INDEX IF NOT EXISTS idx_quiz_attempts_quiz_id  ON public.quiz_attempts (quiz_id);
CREATE INDEX IF NOT EXISTS idx_quiz_attempts_user_id  ON public.quiz_attempts (user_id);
CREATE INDEX IF NOT EXISTS idx_resources_major_id     ON public.resources (major_id);
CREATE INDEX IF NOT EXISTS idx_resources_module_id    ON public.resources (module_id);

-- ============================================================
-- Fix function search_path (security: prevent search_path injection)
-- ============================================================
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER
SET search_path = 'public'
AS $$
BEGIN
  INSERT INTO public.profiles (id, email, full_name, role)
  VALUES (
    NEW.id,
    COALESCE(NEW.email, ''),
    NEW.raw_user_meta_data->>'full_name',
    'student'
  )
  ON CONFLICT (id) DO NOTHING;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE OR REPLACE FUNCTION public.sync_role_to_jwt()
RETURNS TRIGGER
SET search_path = 'public'
AS $$
BEGIN
  UPDATE auth.users
  SET raw_app_meta_data =
      COALESCE(raw_app_meta_data, '{}'::jsonb) || jsonb_build_object('role', NEW.role)
  WHERE id = NEW.id;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE OR REPLACE FUNCTION public.get_my_role()
RETURNS TEXT
LANGUAGE sql
STABLE
SECURITY INVOKER
SET search_path = 'public'
AS $$
  SELECT COALESCE(
    (SELECT auth.jwt()) -> 'app_metadata' ->> 'role',
    'student'
  );
$$;

-- ============================================================
-- Revoke EXECUTE on SECURITY DEFINER functions from anon/authenticated
-- (These are trigger/internal functions, not meant for REST API)
-- ============================================================
REVOKE EXECUTE ON FUNCTION public.handle_new_user() FROM anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.sync_role_to_jwt() FROM anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.set_created_by() FROM anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.rls_auto_enable() FROM anon, authenticated;

-- ============================================================
-- Tighten homework_submissions INSERT policy to require auth
-- ============================================================
DROP POLICY IF EXISTS "Anyone can submit homework" ON public.homework_submissions;
CREATE POLICY "Anyone can submit homework"
  ON public.homework_submissions FOR INSERT
  WITH CHECK ((SELECT auth.uid()) IS NOT NULL);