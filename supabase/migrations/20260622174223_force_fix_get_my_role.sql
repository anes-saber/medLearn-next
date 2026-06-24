-- Force-update get_my_role to read from JWT instead of querying profiles.
-- This avoids infinite recursion in RLS policies.

-- Recreate the function with the JWT-based implementation
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
