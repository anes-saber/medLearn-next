-- ============================================================================
-- Remaining security hardening from Supabase lint audit.
-- Addresses gaps not covered by 20260624000000:
--   1. set_created_by() SECURITY DEFINER missing SET search_path (P0)
--   2. Missing TO clauses on RLS policies — defense-in-depth (P1)
-- ============================================================================

-- ============================================================
-- 1. Fix set_created_by() — add SET search_path to prevent
--    search_path injection attacks on this SECURITY DEFINER
--    trigger function. (Same pattern as handle_new_user /
--    sync_role_to_jwt already fixed in 20260624000000.)
-- ============================================================
CREATE OR REPLACE FUNCTION public.set_created_by()
RETURNS TRIGGER
SET search_path = 'public'
AS $$
BEGIN
  NEW.created_by = auth.uid();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- ============================================================
-- 2. Add TO clauses to RLS policies.
--
--    Without a TO clause, policies default to PUBLIC (all roles).
--    Adding TO authenticated prevents anon users from even
--    evaluating write policies they should never match.
--    Published-content SELECT policies explicitly allow
--    anon + authenticated for transparent intent.
--
--    Policies supporting anonymous quiz-taking
--    (quiz_attempts) intentionally include TO anon.
-- ============================================================

-- --- MAJORS ---
DROP POLICY IF EXISTS "Admin/teacher can insert majors" ON public.majors;
CREATE POLICY "Admin/teacher can insert majors"
  ON public.majors FOR INSERT TO authenticated
  WITH CHECK ((SELECT public.get_my_role()) IN ('admin', 'teacher'));

DROP POLICY IF EXISTS "Admin/teacher can update majors" ON public.majors;
CREATE POLICY "Admin/teacher can update majors"
  ON public.majors FOR UPDATE TO authenticated
  USING  ((SELECT public.get_my_role()) IN ('admin', 'teacher'))
  WITH CHECK ((SELECT public.get_my_role()) IN ('admin', 'teacher'));

DROP POLICY IF EXISTS "Admin/teacher can delete majors" ON public.majors;
CREATE POLICY "Admin/teacher can delete majors"
  ON public.majors FOR DELETE TO authenticated
  USING ((SELECT public.get_my_role()) IN ('admin', 'teacher'));

-- --- MODULES ---
DROP POLICY IF EXISTS "Admin/teacher can insert modules" ON public.modules;
CREATE POLICY "Admin/teacher can insert modules"
  ON public.modules FOR INSERT TO authenticated
  WITH CHECK ((SELECT public.get_my_role()) IN ('admin', 'teacher'));

DROP POLICY IF EXISTS "Admin/teacher can update modules" ON public.modules;
CREATE POLICY "Admin/teacher can update modules"
  ON public.modules FOR UPDATE TO authenticated
  USING  ((SELECT public.get_my_role()) IN ('admin', 'teacher'))
  WITH CHECK ((SELECT public.get_my_role()) IN ('admin', 'teacher'));

DROP POLICY IF EXISTS "Admin/teacher can delete modules" ON public.modules;
CREATE POLICY "Admin/teacher can delete modules"
  ON public.modules FOR DELETE TO authenticated
  USING ((SELECT public.get_my_role()) IN ('admin', 'teacher'));

-- --- RESOURCES ---
DROP POLICY IF EXISTS "Admin/teacher can insert resources" ON public.resources;
CREATE POLICY "Admin/teacher can insert resources"
  ON public.resources FOR INSERT TO authenticated
  WITH CHECK (COALESCE((SELECT auth.jwt()) -> 'app_metadata' ->> 'role', 'student') IN ('admin', 'teacher'));

DROP POLICY IF EXISTS "Admin/teacher can update resources" ON public.resources;
CREATE POLICY "Admin/teacher can update resources"
  ON public.resources FOR UPDATE TO authenticated
  USING  (COALESCE((SELECT auth.jwt()) -> 'app_metadata' ->> 'role', 'student') IN ('admin', 'teacher'))
  WITH CHECK (COALESCE((SELECT auth.jwt()) -> 'app_metadata' ->> 'role', 'student') IN ('admin', 'teacher'));

DROP POLICY IF EXISTS "Admin/teacher can delete resources" ON public.resources;
CREATE POLICY "Admin/teacher can delete resources"
  ON public.resources FOR DELETE TO authenticated
  USING (COALESCE((SELECT auth.jwt()) -> 'app_metadata' ->> 'role', 'student') IN ('admin', 'teacher'));

-- --- QUESTIONS ---
DROP POLICY IF EXISTS "Admin/teacher can insert questions" ON public.questions;
CREATE POLICY "Admin/teacher can insert questions"
  ON public.questions FOR INSERT TO authenticated
  WITH CHECK (COALESCE((SELECT auth.jwt()) -> 'app_metadata' ->> 'role', 'student') IN ('admin', 'teacher'));

DROP POLICY IF EXISTS "Admin/teacher can update questions" ON public.questions;
CREATE POLICY "Admin/teacher can update questions"
  ON public.questions FOR UPDATE TO authenticated
  USING  (COALESCE((SELECT auth.jwt()) -> 'app_metadata' ->> 'role', 'student') IN ('admin', 'teacher'))
  WITH CHECK (COALESCE((SELECT auth.jwt()) -> 'app_metadata' ->> 'role', 'student') IN ('admin', 'teacher'));

DROP POLICY IF EXISTS "Admin/teacher can delete questions" ON public.questions;
CREATE POLICY "Admin/teacher can delete questions"
  ON public.questions FOR DELETE TO authenticated
  USING (COALESCE((SELECT auth.jwt()) -> 'app_metadata' ->> 'role', 'student') IN ('admin', 'teacher'));

-- --- QUIZZES ---
DROP POLICY IF EXISTS "Admin/teacher can insert quizzes" ON public.quizzes;
CREATE POLICY "Admin/teacher can insert quizzes"
  ON public.quizzes FOR INSERT TO authenticated
  WITH CHECK (COALESCE((SELECT auth.jwt()) -> 'app_metadata' ->> 'role', 'student') IN ('admin', 'teacher'));

DROP POLICY IF EXISTS "Admin/teacher can update quizzes" ON public.quizzes;
CREATE POLICY "Admin/teacher can update quizzes"
  ON public.quizzes FOR UPDATE TO authenticated
  USING  (COALESCE((SELECT auth.jwt()) -> 'app_metadata' ->> 'role', 'student') IN ('admin', 'teacher'))
  WITH CHECK (COALESCE((SELECT auth.jwt()) -> 'app_metadata' ->> 'role', 'student') IN ('admin', 'teacher'));

DROP POLICY IF EXISTS "Admin/teacher can delete quizzes" ON public.quizzes;
CREATE POLICY "Admin/teacher can delete quizzes"
  ON public.quizzes FOR DELETE TO authenticated
  USING (COALESCE((SELECT auth.jwt()) -> 'app_metadata' ->> 'role', 'student') IN ('admin', 'teacher'));

-- --- QUIZ QUESTIONS ---
DROP POLICY IF EXISTS "Admin/teacher can insert quiz questions" ON public.quiz_questions;
CREATE POLICY "Admin/teacher can insert quiz questions"
  ON public.quiz_questions FOR INSERT TO authenticated
  WITH CHECK ((SELECT public.get_my_role()) IN ('admin', 'teacher'));

DROP POLICY IF EXISTS "Admin/teacher can update quiz questions" ON public.quiz_questions;
CREATE POLICY "Admin/teacher can update quiz questions"
  ON public.quiz_questions FOR UPDATE TO authenticated
  USING  ((SELECT public.get_my_role()) IN ('admin', 'teacher'))
  WITH CHECK ((SELECT public.get_my_role()) IN ('admin', 'teacher'));

DROP POLICY IF EXISTS "Admin/teacher can delete quiz questions" ON public.quiz_questions;
CREATE POLICY "Admin/teacher can delete quiz questions"
  ON public.quiz_questions FOR DELETE TO authenticated
  USING ((SELECT public.get_my_role()) IN ('admin', 'teacher'));

-- --- HOMEWORKS ---
DROP POLICY IF EXISTS "Admin/teacher can insert homeworks" ON public.homeworks;
CREATE POLICY "Admin/teacher can insert homeworks"
  ON public.homeworks FOR INSERT TO authenticated
  WITH CHECK (COALESCE((SELECT auth.jwt()) -> 'app_metadata' ->> 'role', 'student') IN ('admin', 'teacher'));

DROP POLICY IF EXISTS "Admin/teacher can update homeworks" ON public.homeworks;
CREATE POLICY "Admin/teacher can update homeworks"
  ON public.homeworks FOR UPDATE TO authenticated
  USING  (COALESCE((SELECT auth.jwt()) -> 'app_metadata' ->> 'role', 'student') IN ('admin', 'teacher'))
  WITH CHECK (COALESCE((SELECT auth.jwt()) -> 'app_metadata' ->> 'role', 'student') IN ('admin', 'teacher'));

DROP POLICY IF EXISTS "Admin/teacher can delete homeworks" ON public.homeworks;
CREATE POLICY "Admin/teacher can delete homeworks"
  ON public.homeworks FOR DELETE TO authenticated
  USING (COALESCE((SELECT auth.jwt()) -> 'app_metadata' ->> 'role', 'student') IN ('admin', 'teacher'));

-- --- HOMEWORK SUBMISSIONS ---
DROP POLICY IF EXISTS "Anyone can submit homework" ON public.homework_submissions;
CREATE POLICY "Anyone can submit homework"
  ON public.homework_submissions FOR INSERT TO authenticated
  WITH CHECK ((SELECT auth.uid()) IS NOT NULL);

DROP POLICY IF EXISTS "Admin/teacher can update submissions" ON public.homework_submissions;
CREATE POLICY "Admin/teacher can update submissions"
  ON public.homework_submissions FOR UPDATE TO authenticated
  USING  ((SELECT public.get_my_role()) IN ('admin', 'teacher'))
  WITH CHECK ((SELECT public.get_my_role()) IN ('admin', 'teacher'));

DROP POLICY IF EXISTS "Admin/teacher can delete submissions" ON public.homework_submissions;
CREATE POLICY "Admin/teacher can delete submissions"
  ON public.homework_submissions FOR DELETE TO authenticated
  USING ((SELECT public.get_my_role()) IN ('admin', 'teacher'));

-- --- PROFILES ---
DROP POLICY IF EXISTS "Admin/teacher can update profiles" ON public.profiles;
CREATE POLICY "Admin/teacher can update profiles"
  ON public.profiles FOR UPDATE TO authenticated
  USING  (COALESCE((SELECT auth.jwt()) -> 'app_metadata' ->> 'role', 'student') IN ('admin', 'teacher'))
  WITH CHECK (COALESCE((SELECT auth.jwt()) -> 'app_metadata' ->> 'role', 'student') IN ('admin', 'teacher'));

-- --- STORAGE (resources bucket) ---
DROP POLICY IF EXISTS "Admin/teacher can manage resources bucket" ON storage.objects;
CREATE POLICY "Admin/teacher can manage resources bucket"
  ON storage.objects FOR ALL TO authenticated
  USING  (bucket_id = 'resources' AND COALESCE((SELECT auth.jwt()) -> 'app_metadata' ->> 'role', 'student') IN ('admin', 'teacher'))
  WITH CHECK (bucket_id = 'resources' AND COALESCE((SELECT auth.jwt()) -> 'app_metadata' ->> 'role', 'student') IN ('admin', 'teacher'));

-- ============================================================
-- 3. Add TO clauses to SELECT policies for explicit role intent.
--    Published-content policies: TO anon, authenticated.
--    Reference data (majors/modules): TO anon, authenticated.
--    Anonymous quiz support (quiz_attempts): TO anon, authenticated.
-- ============================================================

DROP POLICY IF EXISTS "Anyone can view majors" ON public.majors;
CREATE POLICY "Anyone can view majors"
  ON public.majors FOR SELECT TO anon, authenticated
  USING (true);

DROP POLICY IF EXISTS "Anyone can view modules" ON public.modules;
CREATE POLICY "Anyone can view modules"
  ON public.modules FOR SELECT TO anon, authenticated
  USING (true);

DROP POLICY IF EXISTS "View published or own resources" ON public.resources;
CREATE POLICY "View published or own resources"
  ON public.resources FOR SELECT TO anon, authenticated
  USING (
    published = true
    OR COALESCE((SELECT auth.jwt()) -> 'app_metadata' ->> 'role', 'student') IN ('admin', 'teacher')
  );

DROP POLICY IF EXISTS "Anyone can view published questions" ON public.questions;
CREATE POLICY "Anyone can view published questions"
  ON public.questions FOR SELECT TO anon, authenticated
  USING (published = true OR COALESCE((SELECT auth.jwt()) -> 'app_metadata' ->> 'role', 'student') IN ('admin', 'teacher'));

DROP POLICY IF EXISTS "Anyone can view published quizzes" ON public.quizzes;
CREATE POLICY "Anyone can view published quizzes"
  ON public.quizzes FOR SELECT TO anon, authenticated
  USING (published = true OR COALESCE((SELECT auth.jwt()) -> 'app_metadata' ->> 'role', 'student') IN ('admin', 'teacher'));

DROP POLICY IF EXISTS "View quiz questions" ON public.quiz_questions;
CREATE POLICY "View quiz questions"
  ON public.quiz_questions FOR SELECT TO anon, authenticated
  USING (
    EXISTS (
      SELECT 1 FROM public.quizzes q
      WHERE q.id = quiz_id
        AND (q.published = true OR (SELECT public.get_my_role()) IN ('admin', 'teacher'))
    )
  );

DROP POLICY IF EXISTS "Anyone can view published homeworks" ON public.homeworks;
CREATE POLICY "Anyone can view published homeworks"
  ON public.homeworks FOR SELECT TO anon, authenticated
  USING (published = true OR COALESCE((SELECT auth.jwt()) -> 'app_metadata' ->> 'role', 'student') IN ('admin', 'teacher'));

DROP POLICY IF EXISTS "Users see own submissions, admin/teacher see all" ON public.homework_submissions;
CREATE POLICY "Users see own submissions, admin/teacher see all"
  ON public.homework_submissions FOR SELECT TO anon, authenticated
  USING (
    user_id = (SELECT auth.uid())
    OR (SELECT public.get_my_role()) IN ('admin', 'teacher')
  );

DROP POLICY IF EXISTS "View quiz attempts" ON public.quiz_attempts;
CREATE POLICY "View quiz attempts"
  ON public.quiz_attempts FOR SELECT TO anon, authenticated
  USING (
    (SELECT auth.uid()) = user_id
    OR ((SELECT auth.uid()) IS NULL AND user_id IS NULL)
    OR (SELECT public.get_my_role()) IN ('teacher', 'admin')
  );

DROP POLICY IF EXISTS "Insert quiz attempts" ON public.quiz_attempts;
CREATE POLICY "Insert quiz attempts"
  ON public.quiz_attempts FOR INSERT TO anon, authenticated
  WITH CHECK (
    (SELECT auth.uid()) = user_id
    OR ((SELECT auth.uid()) IS NULL AND user_id IS NULL)
  );

DROP POLICY IF EXISTS "Users can view own profile, admin/teacher can view all" ON public.profiles;
CREATE POLICY "Users can view own profile, admin/teacher can view all"
  ON public.profiles FOR SELECT TO anon, authenticated
  USING (
    (SELECT auth.uid()) = id
    OR (SELECT public.get_my_role()) IN ('admin', 'teacher')
  );
