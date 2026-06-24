-- ============================================================================
-- Fix infinite recursion in RLS policies on profiles table
--
-- Root cause: get_my_role() queries public.profiles, but the RLS policy
-- "Admin/teacher can read all profiles" on profiles calls get_my_role(),
-- creating infinite recursion.
--
-- Fix: sync profiles.role to auth.users.raw_app_meta_data (included in JWT),
--       then rewrite get_my_role() to read from the JWT instead of querying
--       the profiles table. This completely breaks the recursion cycle.
-- ============================================================================
BEGIN;

-- ============================================================
-- 1. Trigger to sync profiles.role to auth.users.raw_app_meta_data
--    (so it's included in the JWT as app_metadata.role)
-- ============================================================
CREATE OR REPLACE FUNCTION public.sync_role_to_jwt()
RETURNS TRIGGER AS $$
BEGIN
  UPDATE auth.users
  SET raw_app_meta_data =
      COALESCE(raw_app_meta_data, '{}'::jsonb) || jsonb_build_object('role', NEW.role)
  WHERE id = NEW.id;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

DROP TRIGGER IF EXISTS sync_role_to_jwt ON public.profiles;
CREATE TRIGGER sync_role_to_jwt
  AFTER INSERT OR UPDATE OF role ON public.profiles
  FOR EACH ROW
  EXECUTE FUNCTION public.sync_role_to_jwt();

-- ============================================================
-- 2. Backfill existing users' roles into raw_app_meta_data
-- ============================================================
UPDATE auth.users u
SET raw_app_meta_data =
    COALESCE(u.raw_app_meta_data, '{}'::jsonb) || jsonb_build_object('role', p.role)
FROM public.profiles p
WHERE u.id = p.id
  AND COALESCE(u.raw_app_meta_data ->> 'role', '') != p.role;

-- ============================================================
-- 3. Rewrite get_my_role() to read from JWT instead of profiles
--    No SECURITY DEFINER needed — auth.jwt() reads from request context,
--    not from any table, so there's no risk of RLS recursion.
-- ============================================================
CREATE OR REPLACE FUNCTION public.get_my_role()
RETURNS TEXT
LANGUAGE sql
STABLE
AS $$
  SELECT COALESCE(
    auth.jwt() -> 'app_metadata' ->> 'role',
    'student'
  );
$$;

COMMIT;
