-- Temporarily set get_my_role to return a constant to isolate the recursion issue
CREATE OR REPLACE FUNCTION public.get_my_role()
RETURNS TEXT
LANGUAGE sql
STABLE
SECURITY INVOKER
AS $$
  SELECT 'student';
$$;
