-- Bypass get_my_role() in all RLS policies, using auth.jwt() directly
-- to isolate whether the recursion is caused by the function call itself

-- ==================== RESOURCES ====================
DROP POLICY IF EXISTS "View published or own resources" ON public.resources;
DROP POLICY IF EXISTS "Admin/teacher can insert resources" ON public.resources;
DROP POLICY IF EXISTS "Admin/teacher can update resources" ON public.resources;
DROP POLICY IF EXISTS "Admin/teacher can delete resources" ON public.resources;

CREATE POLICY "View published or own resources"
  ON public.resources FOR SELECT
  USING (
    published = true
    OR COALESCE(auth.jwt() -> 'app_metadata' ->> 'role', 'student') IN ('admin', 'teacher')
  );

CREATE POLICY "Admin/teacher can insert resources"
  ON public.resources FOR INSERT
  WITH CHECK (COALESCE(auth.jwt() -> 'app_metadata' ->> 'role', 'student') IN ('admin', 'teacher'));

CREATE POLICY "Admin/teacher can update resources"
  ON public.resources FOR UPDATE
  USING  (COALESCE(auth.jwt() -> 'app_metadata' ->> 'role', 'student') IN ('admin', 'teacher'))
  WITH CHECK (COALESCE(auth.jwt() -> 'app_metadata' ->> 'role', 'student') IN ('admin', 'teacher'));

CREATE POLICY "Admin/teacher can delete resources"
  ON public.resources FOR DELETE
  USING (COALESCE(auth.jwt() -> 'app_metadata' ->> 'role', 'student') IN ('admin', 'teacher'));

-- ==================== HOMEWORKS ====================
DROP POLICY IF EXISTS "Anyone can view published homeworks" ON public.homeworks;
DROP POLICY IF EXISTS "Admin/teacher can insert homeworks" ON public.homeworks;
DROP POLICY IF EXISTS "Admin/teacher can update homeworks" ON public.homeworks;
DROP POLICY IF EXISTS "Admin/teacher can delete homeworks" ON public.homeworks;

CREATE POLICY "Anyone can view published homeworks"
  ON public.homeworks FOR SELECT
  USING (published = true OR COALESCE(auth.jwt() -> 'app_metadata' ->> 'role', 'student') IN ('admin', 'teacher'));

CREATE POLICY "Admin/teacher can insert homeworks"
  ON public.homeworks FOR INSERT
  WITH CHECK (COALESCE(auth.jwt() -> 'app_metadata' ->> 'role', 'student') IN ('admin', 'teacher'));

CREATE POLICY "Admin/teacher can update homeworks"
  ON public.homeworks FOR UPDATE
  USING  (COALESCE(auth.jwt() -> 'app_metadata' ->> 'role', 'student') IN ('admin', 'teacher'))
  WITH CHECK (COALESCE(auth.jwt() -> 'app_metadata' ->> 'role', 'student') IN ('admin', 'teacher'));

CREATE POLICY "Admin/teacher can delete homeworks"
  ON public.homeworks FOR DELETE
  USING (COALESCE(auth.jwt() -> 'app_metadata' ->> 'role', 'student') IN ('admin', 'teacher'));

-- ==================== QUIZZES ====================
DROP POLICY IF EXISTS "Anyone can view published quizzes" ON public.quizzes;
DROP POLICY IF EXISTS "Admin/teacher can insert quizzes" ON public.quizzes;
DROP POLICY IF EXISTS "Admin/teacher can update quizzes" ON public.quizzes;
DROP POLICY IF EXISTS "Admin/teacher can delete quizzes" ON public.quizzes;

CREATE POLICY "Anyone can view published quizzes"
  ON public.quizzes FOR SELECT
  USING (published = true OR COALESCE(auth.jwt() -> 'app_metadata' ->> 'role', 'student') IN ('admin', 'teacher'));

CREATE POLICY "Admin/teacher can insert quizzes"
  ON public.quizzes FOR INSERT
  WITH CHECK (COALESCE(auth.jwt() -> 'app_metadata' ->> 'role', 'student') IN ('admin', 'teacher'));

CREATE POLICY "Admin/teacher can update quizzes"
  ON public.quizzes FOR UPDATE
  USING  (COALESCE(auth.jwt() -> 'app_metadata' ->> 'role', 'student') IN ('admin', 'teacher'))
  WITH CHECK (COALESCE(auth.jwt() -> 'app_metadata' ->> 'role', 'student') IN ('admin', 'teacher'));

CREATE POLICY "Admin/teacher can delete quizzes"
  ON public.quizzes FOR DELETE
  USING (COALESCE(auth.jwt() -> 'app_metadata' ->> 'role', 'student') IN ('admin', 'teacher'));

-- ==================== QUESTIONS ====================
DROP POLICY IF EXISTS "Anyone can view published questions" ON public.questions;
DROP POLICY IF EXISTS "Admin/teacher can insert questions" ON public.questions;
DROP POLICY IF EXISTS "Admin/teacher can update questions" ON public.questions;
DROP POLICY IF EXISTS "Admin/teacher can delete questions" ON public.questions;

CREATE POLICY "Anyone can view published questions"
  ON public.questions FOR SELECT
  USING (published = true OR COALESCE(auth.jwt() -> 'app_metadata' ->> 'role', 'student') IN ('admin', 'teacher'));

CREATE POLICY "Admin/teacher can insert questions"
  ON public.questions FOR INSERT
  WITH CHECK (COALESCE(auth.jwt() -> 'app_metadata' ->> 'role', 'student') IN ('admin', 'teacher'));

CREATE POLICY "Admin/teacher can update questions"
  ON public.questions FOR UPDATE
  USING  (COALESCE(auth.jwt() -> 'app_metadata' ->> 'role', 'student') IN ('admin', 'teacher'))
  WITH CHECK (COALESCE(auth.jwt() -> 'app_metadata' ->> 'role', 'student') IN ('admin', 'teacher'));

CREATE POLICY "Admin/teacher can delete questions"
  ON public.questions FOR DELETE
  USING (COALESCE(auth.jwt() -> 'app_metadata' ->> 'role', 'student') IN ('admin', 'teacher'));
