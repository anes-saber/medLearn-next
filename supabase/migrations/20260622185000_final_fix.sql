-- Final fix: restore get_my_role() to JWT version and recreate profiles policies
-- using auth.jwt() directly to avoid any recursion risk.

-- ============================================================
-- 1. Restore get_my_role() to read from JWT
-- ============================================================
CREATE OR REPLACE FUNCTION public.get_my_role()
RETURNS TEXT
LANGUAGE sql
STABLE
SECURITY INVOKER
AS $$
  SELECT COALESCE(
    auth.jwt() -> 'app_metadata' ->> 'role',
    'student'
  );
$$;

-- ============================================================
-- 2. Recreate profiles policies using auth.jwt() directly
--    (instead of calling get_my_role()) to prevent any recursion
-- ============================================================
CREATE POLICY "Users can read own profile"
  ON public.profiles FOR SELECT
  USING (auth.uid() = id);

CREATE POLICY "Admin/teacher can read all profiles"
  ON public.profiles FOR SELECT
  USING (COALESCE(auth.jwt() -> 'app_metadata' ->> 'role', 'student') IN ('admin', 'teacher'));

CREATE POLICY "Admin/teacher can update any profile"
  ON public.profiles FOR UPDATE
  USING  (COALESCE(auth.jwt() -> 'app_metadata' ->> 'role', 'student') IN ('admin', 'teacher'))
  WITH CHECK (COALESCE(auth.jwt() -> 'app_metadata' ->> 'role', 'student') IN ('admin', 'teacher'));
